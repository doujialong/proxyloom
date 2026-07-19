package fetcher

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const (
	DefaultMaxBytes = 10 << 20
	HardMaxBytes    = 50 << 20
	MaxHeaders      = 32
	MaxHeaderBytes  = 32 << 10
	DefaultTimeout  = 30 * time.Second
)

var ErrNetworkPolicy = errors.New("remote source violates network policy")

type Options struct {
	Timeout                  time.Duration
	MaxBytes                 int
	PrivateNetworkAuthorized bool
	Resolver                 *net.Resolver
	Headers                  map[string]string
	ProxyURL                 string
}

type Result struct {
	Content     []byte
	StatusCode  int
	ContentType string
	Elapsed     time.Duration
}

func Fetch(ctx context.Context, rawURL string, options Options) (Result, error) {
	if options.Timeout <= 0 {
		options.Timeout = DefaultTimeout
	}
	if options.MaxBytes <= 0 {
		options.MaxBytes = DefaultMaxBytes
	}
	if options.MaxBytes > HardMaxBytes {
		options.MaxBytes = HardMaxBytes
	}
	if options.Resolver == nil {
		options.Resolver = net.DefaultResolver
	}
	parsed, err := validateURL(rawURL)
	if err != nil {
		return Result{}, err
	}
	requestHeaders, customHeaderNames, err := prepareRequestHeaders(options.Headers)
	if err != nil {
		return Result{}, err
	}
	dialer := &policyDialer{
		resolver: options.Resolver, timeout: options.Timeout,
		privateAuthorized: options.PrivateNetworkAuthorized,
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, DisableKeepAlives: true,
		ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	proxyURL, err := validateProxyURL(options.ProxyURL)
	if err != nil {
		return Result{}, err
	}
	if proxyURL != nil {
		if err := authorizeURLDestination(ctx, parsed, options.Resolver, options.PrivateNetworkAuthorized); err != nil {
			return Result{}, err
		}
		switch proxyURL.Scheme {
		case "http", "https":
			transport.Proxy = http.ProxyURL(proxyURL)
		case "socks5", "socks5h":
			proxyDialer, err := newSOCKSProxyDialer(proxyURL, dialer)
			if err != nil {
				return Result{}, err
			}
			transport.DialContext = socksDialContext(proxyDialer, proxyURL.Scheme == "socks5h", options.Resolver, options.PrivateNetworkAuthorized)
		}
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: options.Timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("remote source exceeded 5 redirects")
			}
			if _, err := validateURL(request.URL.String()); err != nil {
				return err
			}
			if proxyURL != nil {
				if err := authorizeURLDestination(request.Context(), request.URL, options.Resolver, options.PrivateNetworkAuthorized); err != nil {
					return err
				}
			}
			if len(via) > 0 {
				stripCrossAuthorityHeaders(request, via[len(via)-1], customHeaderNames)
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("create remote source request: %w", err)
	}
	request.Header.Set("User-Agent", "ProxyLoom/preview")
	request.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.1")
	for name, values := range requestHeaders {
		request.Header[name] = append([]string(nil), values...)
	}
	started := time.Now()
	response, err := client.Do(request)
	elapsed := time.Since(started)
	if err != nil {
		if errors.Is(err, ErrNetworkPolicy) {
			return Result{}, fmt.Errorf("fetch remote source: %w", ErrNetworkPolicy)
		}
		var networkError net.Error
		if (errors.As(err, &networkError) && networkError.Timeout()) || errors.Is(err, context.DeadlineExceeded) {
			return Result{}, fmt.Errorf("remote source request timed out")
		}
		return Result{}, fmt.Errorf("remote source request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return Result{StatusCode: response.StatusCode, Elapsed: elapsed}, fmt.Errorf("remote source returned HTTP %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, int64(options.MaxBytes)+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return Result{}, fmt.Errorf("read remote source response: %w", err)
	}
	if len(content) > options.MaxBytes {
		return Result{}, fmt.Errorf("remote source exceeds %d bytes", options.MaxBytes)
	}
	return Result{
		Content: content, StatusCode: response.StatusCode,
		ContentType: response.Header.Get("Content-Type"), Elapsed: elapsed,
	}, nil
}

func ValidateHeaders(headers map[string]string) error {
	_, _, err := prepareRequestHeaders(headers)
	return err
}

func ValidateProxyURL(raw string) error {
	_, err := validateProxyURL(raw)
	return err
}

func validateProxyURL(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%w: invalid proxy URL", ErrNetworkPolicy)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "socks5" && parsed.Scheme != "socks5h" {
		return nil, fmt.Errorf("%w: proxy must use HTTP, HTTPS, SOCKS5 or SOCKS5H", ErrNetworkPolicy)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf("%w: proxy URL cannot contain a path, query, or fragment", ErrNetworkPolicy)
	}
	if strings.Contains(parsed.Hostname(), "%") || net.ParseIP(parsed.Hostname()) == nil && strings.Contains(parsed.Hostname(), ":") {
		return nil, fmt.Errorf("%w: ambiguous proxy host", ErrNetworkPolicy)
	}
	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			port = "1080"
		}
		parsed.Host = net.JoinHostPort(parsed.Hostname(), port)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("%w: invalid proxy port", ErrNetworkPolicy)
	}
	return parsed, nil
}

func authorizeURLDestination(ctx context.Context, destination *url.URL, resolver *net.Resolver, privateAuthorized bool) error {
	addresses, err := resolver.LookupIPAddr(ctx, destination.Hostname())
	if err != nil {
		return fmt.Errorf("resolve remote source host: %w", err)
	}
	if len(addresses) == 0 {
		return fmt.Errorf("remote source host has no addresses")
	}
	if _, err := allowedIPs(addresses, privateAuthorized); err != nil {
		return err
	}
	return nil
}

func newSOCKSProxyDialer(proxyURL *url.URL, forward xproxy.Dialer) (xproxy.ContextDialer, error) {
	var authentication *xproxy.Auth
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		authentication = &xproxy.Auth{User: proxyURL.User.Username(), Password: password}
	}
	dialer, err := xproxy.SOCKS5("tcp", proxyURL.Host, authentication, forward)
	if err != nil {
		return nil, fmt.Errorf("create SOCKS proxy dialer: %w", err)
	}
	contextDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS proxy dialer does not support request cancellation")
	}
	return contextDialer, nil
}

func socksDialContext(dialer xproxy.ContextDialer, remoteDNS bool, resolver *net.Resolver, privateAuthorized bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid destination authority", ErrNetworkPolicy)
		}
		addresses, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve remote source host: %w", err)
		}
		allowed, err := allowedIPs(addresses, privateAuthorized)
		if err != nil {
			return nil, err
		}
		if remoteDNS {
			return dialer.DialContext(ctx, network, address)
		}
		var lastErr error
		for _, ip := range allowed {
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return connection, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

func prepareRequestHeaders(input map[string]string) (http.Header, map[string]struct{}, error) {
	if len(input) > MaxHeaders {
		return nil, nil, fmt.Errorf("remote source request has more than %d headers", MaxHeaders)
	}
	result := make(http.Header, len(input))
	names := make(map[string]struct{}, len(input))
	totalBytes := 0
	for rawName, value := range input {
		name := http.CanonicalHeaderKey(strings.TrimSpace(rawName))
		if !validHeaderName(name) {
			return nil, nil, fmt.Errorf("remote source request contains an invalid header name")
		}
		if _, forbidden := forbiddenRequestHeaders[strings.ToLower(name)]; forbidden {
			return nil, nil, fmt.Errorf("remote source request header %q is not allowed", name)
		}
		if _, duplicate := names[name]; duplicate {
			return nil, nil, fmt.Errorf("remote source request contains duplicate header %q", name)
		}
		if len(value) > 8<<10 || !validHeaderValue(value) {
			return nil, nil, fmt.Errorf("remote source request header %q has an invalid value", name)
		}
		totalBytes += len(name) + len(value)
		if totalBytes > MaxHeaderBytes {
			return nil, nil, fmt.Errorf("remote source request headers exceed %d bytes", MaxHeaderBytes)
		}
		result.Set(name, value)
		names[name] = struct{}{}
	}
	return result, names, nil
}

func validHeaderName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if !isTokenCharacter(character) {
			return false
		}
	}
	return true
}

func isTokenCharacter(value byte) bool {
	if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' {
		return true
	}
	switch value {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func validHeaderValue(value string) bool {
	for _, character := range []byte(value) {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func stripCrossAuthorityHeaders(request, previous *http.Request, customHeaderNames map[string]struct{}) {
	if request == nil || previous == nil || sameAuthority(previous.URL, request.URL) {
		return
	}
	request.Header.Del("Authorization")
	request.Header.Del("Cookie")
	for name := range customHeaderNames {
		request.Header.Del(name)
	}
}

var forbiddenRequestHeaders = map[string]struct{}{
	"connection": {}, "content-length": {}, "host": {}, "keep-alive": {},
	"proxy-authorization": {}, "proxy-connection": {}, "te": {},
	"trailer": {}, "transfer-encoding": {}, "upgrade": {},
}

type policyDialer struct {
	resolver          *net.Resolver
	timeout           time.Duration
	privateAuthorized bool
}

func (d *policyDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *policyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid destination authority", ErrNetworkPolicy)
	}
	addresses, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve remote source host: %w", err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("remote source host has no addresses")
	}
	allowed, err := allowedIPs(addresses, d.privateAuthorized)
	if err != nil {
		return nil, err
	}
	return dialAllowedIPs(ctx, network, port, allowed, d.timeout)
}

func selectAllowedIP(addresses []net.IPAddr, privateAuthorized bool) (net.IP, error) {
	allowed, err := allowedIPs(addresses, privateAuthorized)
	if err != nil {
		return nil, err
	}
	return allowed[0], nil
}

func allowedIPs(addresses []net.IPAddr, privateAuthorized bool) ([]net.IP, error) {
	result := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		if err := allowIP(address.IP, privateAuthorized); err == nil {
			result = append(result, address.IP)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%w: destination has no authorized addresses", ErrNetworkPolicy)
	}
	return result, nil
}

func dialAllowedIPs(ctx context.Context, network, port string, addresses []net.IP, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type attempt struct {
		connection net.Conn
		err        error
	}
	results := make(chan attempt, len(addresses))
	for _, address := range addresses {
		destination := net.JoinHostPort(address.String(), port)
		go func() {
			dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
			connection, err := dialer.DialContext(ctx, network, destination)
			results <- attempt{connection: connection, err: err}
		}()
	}
	var lastErr error
	for range addresses {
		result := <-results
		if result.err == nil {
			cancel()
			return result.connection, nil
		}
		lastErr = result.err
	}
	return nil, lastErr
}

func validateURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("%w: invalid HTTP URL", ErrNetworkPolicy)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: only HTTP and HTTPS are allowed", ErrNetworkPolicy)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: userinfo and fragments are not allowed", ErrNetworkPolicy)
	}
	if strings.Contains(parsed.Hostname(), "%") || net.ParseIP(parsed.Hostname()) == nil && strings.Contains(parsed.Hostname(), ":") {
		return nil, fmt.Errorf("%w: ambiguous host", ErrNetworkPolicy)
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("%w: invalid port", ErrNetworkPolicy)
	}
	if portNumber != 80 && portNumber != 443 {
		return nil, fmt.Errorf("%w: only ports 80 and 443 are allowed", ErrNetworkPolicy)
	}
	return parsed, nil
}

func allowIP(ip net.IP, privateAuthorized bool) error {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("%w: unusable destination address", ErrNetworkPolicy)
	}
	if isNonPublic(ip) && !privateAuthorized {
		return fmt.Errorf("%w: non-public destination requires source authorization", ErrNetworkPolicy)
	}
	return nil
}

func isNonPublic(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, network := range specialNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

var specialNetworks = mustNetworks(
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
	"::/128", "2001:db8::/32",
)

func mustNetworks(values ...string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		result = append(result, network)
	}
	return result
}

func sameAuthority(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}
