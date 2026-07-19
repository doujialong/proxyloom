package fetcher

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFetchRequiresExplicitPrivateNetworkAuthorization(t *testing.T) {
	_, err := Fetch(context.Background(), "http://127.0.0.1/source-secret-token", Options{Timeout: time.Second})
	if err == nil || !errors.Is(err, ErrNetworkPolicy) {
		t.Fatalf("Fetch() without authorization error = %v", err)
	}
	if strings.Contains(err.Error(), "source-secret-token") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("Fetch() error leaked source URL details: %v", err)
	}
}

func TestPrepareRequestHeadersAndCrossAuthorityPolicy(t *testing.T) {
	headers, names, err := prepareRequestHeaders(map[string]string{
		"authorization": "Basic secret", "Cookie": "session=secret",
		"User-Agent": "Private Client", "X-Source-Key": "secret-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{Header: headers, URL: &url.URL{Scheme: "https", Host: "other.example"}}
	previous := &http.Request{URL: &url.URL{Scheme: "https", Host: "source.example"}}
	if sameAuthority(previous.URL, request.URL) {
		t.Fatal("fixture authorities unexpectedly match")
	}
	stripCrossAuthorityHeaders(request, previous, names)
	if len(request.Header) != 0 {
		t.Fatalf("cross-authority headers were retained: %v", request.Header)
	}
}

func TestValidateHeadersRejectsUnsafeValues(t *testing.T) {
	tests := []map[string]string{
		{"Host": "internal.example"},
		{"Connection": "keep-alive"},
		{"X-Test\r\nInjected": "value"},
		{"Authorization": "Basic ok\r\nX-Injected: yes"},
	}
	for _, headers := range tests {
		if err := ValidateHeaders(headers); err == nil {
			t.Fatalf("ValidateHeaders(%v) succeeded", headers)
		}
	}
}

func TestValidateURLRejectsUnsafeSchemesAndPorts(t *testing.T) {
	for _, value := range []string{"file:///tmp/source", "http://user:secret@example.test/", "http://example.test:8080/"} {
		if _, err := validateURL(value); err == nil {
			t.Fatalf("validateURL(%q) succeeded", value)
		}
	}
}

func TestValidateProxyURL(t *testing.T) {
	for _, value := range []string{
		"http://proxy.example", "https://user:secret@proxy.example:8443",
		"socks5://127.0.0.1:1080", "socks5h://proxy.example",
	} {
		if err := ValidateProxyURL(value); err != nil {
			t.Fatalf("ValidateProxyURL(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{
		"ftp://proxy.example", "socks5://proxy.example/path", "http://proxy.example:70000",
	} {
		if err := ValidateProxyURL(value); err == nil {
			t.Fatalf("ValidateProxyURL(%q) succeeded", value)
		}
	}
}

func TestAllowIPPolicy(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "192.0.2.1", "::1"} {
		ip := mustParseIP(t, value)
		if err := allowIP(ip, false); !errors.Is(err, ErrNetworkPolicy) {
			t.Fatalf("allowIP(%s, false) error = %v", value, err)
		}
	}
	if err := allowIP(mustParseIP(t, "10.0.0.1"), true); err != nil {
		t.Fatalf("allowIP(private authorized) error = %v", err)
	}
}

func TestSelectAllowedIPSkipsUnauthorizedFakeAddress(t *testing.T) {
	public := mustParseIP(t, "185.199.108.133")
	selected, err := selectAllowedIP([]net.IPAddr{
		{IP: mustParseIP(t, "fc00::a2")},
		{IP: public},
	}, false)
	if err != nil || !selected.Equal(public) {
		t.Fatalf("selectAllowedIP() = %v, %v", selected, err)
	}
	if _, err := selectAllowedIP([]net.IPAddr{{IP: mustParseIP(t, "fc00::a2")}}, false); !errors.Is(err, ErrNetworkPolicy) {
		t.Fatalf("selectAllowedIP(private only) error = %v", err)
	}
}

func TestDialAllowedIPsUsesReachableAddress(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()

	connection, err := dialAllowedIPs(context.Background(), "tcp", strconv.Itoa(port), []net.IP{
		mustParseIP(t, "192.0.2.1"), mustParseIP(t, "127.0.0.1"),
	}, time.Second)
	if err != nil {
		t.Fatalf("dial allowed addresses: %v", err)
	}
	connection.Close()
	select {
	case serverConnection := <-accepted:
		serverConnection.Close()
	case <-time.After(time.Second):
		t.Fatal("reachable address was not accepted")
	}
}

func mustParseIP(t *testing.T, value string) net.IP {
	t.Helper()
	parsed := net.ParseIP(value)
	if parsed == nil {
		t.Fatalf("invalid fixture IP %s", value)
	}
	return parsed
}
