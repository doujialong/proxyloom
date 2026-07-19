package convert

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/doujialong/proxyloom/internal/format/urilist"
)

func URIToSingBox(nodes []urilist.RawNode, names map[int]string) ([]byte, error) {
	outbounds, err := URIOutbounds(nodes, names)
	if err != nil {
		return nil, err
	}
	return RenderSingBox(outbounds)
}

func URIOutbounds(nodes []urilist.RawNode, names map[int]string) ([]Outbound, error) {
	outbounds := make([]Outbound, 0, len(nodes))
	for _, node := range nodes {
		name := names[node.Ordinal]
		if name == "" {
			return nil, fmt.Errorf("URI node %d has no allocated output name", node.Ordinal)
		}
		outbound, err := convertURINode(node, name)
		if err != nil {
			return nil, fmt.Errorf("convert URI node %d (%s): %w", node.Ordinal, node.ProtocolID, err)
		}
		outbounds = append(outbounds, outbound)
	}
	return outbounds, nil
}

func convertURINode(node urilist.RawNode, name string) (Outbound, error) {
	switch strings.ToLower(node.RawType) {
	case "vmess":
		return convertVMessURI(node.Raw, name)
	case "ss":
		return convertShadowsocksURI(node.Raw, name)
	}
	parsed, err := url.Parse(string(node.Raw))
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("URI has no valid server authority")
	}
	portText := parsed.Port()
	if portText == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "http":
			portText = "80"
		case "https":
			portText = "443"
		}
	}
	port, err := parsePort(portText)
	if err != nil {
		return nil, err
	}
	typeName := mapURIType(node.RawType)
	if typeName == "" {
		return nil, fmt.Errorf("URI scheme %q cannot be represented by sing-box", node.RawType)
	}
	outbound := Outbound{"type": typeName, "tag": name, "server": parsed.Hostname(), "server_port": port}
	username := ""
	password := ""
	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
	}
	switch typeName {
	case "vless", "vmess":
		setString(outbound, "uuid", username)
	case "trojan", "hysteria2", "anytls":
		credential := username
		if password != "" {
			credential = password
		}
		setString(outbound, "password", credential)
	case "tuic":
		setString(outbound, "uuid", username)
		setString(outbound, "password", password)
	case "socks", "http", "naive":
		setString(outbound, "username", username)
		setString(outbound, "password", password)
	}
	query := parsed.Query()
	if err := validateURIQuery(query); err != nil {
		return nil, err
	}
	setString(outbound, "flow", query.Get("flow"))
	setString(outbound, "packet_encoding", firstNonEmpty(query.Get("packetEncoding"), query.Get("packet_encoding")))
	if typeName == "hysteria2" {
		if rawPorts := splitList(firstNonEmpty(query.Get("ports"), query.Get("mport"))); len(rawPorts) > 0 {
			ports, err := normalizeHysteria2ServerPorts(rawPorts)
			if err != nil {
				return nil, err
			}
			outbound["server_ports"] = ports
		}
		setString(outbound, "hop_interval", normalizeSecondDuration(firstNonEmpty(query.Get("hop_interval"), query.Get("hop-interval"))))
		obfsType := query.Get("obfs")
		obfsPassword := firstNonEmpty(query.Get("obfs-password"), query.Get("obfs_password"))
		if obfsType != "" || obfsPassword != "" {
			outbound["obfs"] = map[string]interface{}{"type": obfsType, "password": obfsPassword}
		}
	}
	if typeName == "tuic" {
		setString(outbound, "congestion_control", firstNonEmpty(query.Get("congestion_control"), query.Get("congestion-controller")))
		setString(outbound, "udp_relay_mode", firstNonEmpty(query.Get("udp_relay_mode"), query.Get("udp-relay-mode")))
	}
	tls := uriTLS(query)
	if strings.EqualFold(parsed.Scheme, "https") && tls == nil {
		tls = map[string]interface{}{"enabled": true}
	}
	if tls != nil {
		outbound["tls"] = tls
	}
	if transport := uriTransport(query); transport != nil {
		outbound["transport"] = transport
	}
	return outbound, nil
}

func convertVMessURI(raw []byte, name string) (Outbound, error) {
	value := string(raw)
	payload := strings.TrimPrefix(value, "vmess://")
	if marker := strings.IndexByte(payload, '#'); marker >= 0 {
		payload = payload[:marker]
	}
	decoded, err := decodeFlexibleBase64(payload)
	if err != nil {
		return nil, fmt.Errorf("decode VMess JSON payload: %w", err)
	}
	var source map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(string(decoded)))
	decoder.UseNumber()
	if err := decoder.Decode(&source); err != nil {
		return nil, fmt.Errorf("decode VMess JSON: %w", err)
	}
	server := stringValue(source["add"])
	port, err := parsePort(stringValue(source["port"]))
	if err != nil {
		return nil, err
	}
	outbound := Outbound{
		"type": "vmess", "tag": name, "server": server, "server_port": port,
		"uuid": stringValue(source["id"]),
	}
	setString(outbound, "security", stringValue(source["scy"]))
	if alterID, err := strconv.Atoi(stringValue(source["aid"])); err == nil {
		outbound["alter_id"] = alterID
	}
	tlsName := stringValue(source["tls"])
	serverName := stringValue(source["sni"])
	if tlsName != "" && tlsName != "none" || serverName != "" {
		tls := map[string]interface{}{"enabled": true}
		setMapString(tls, "server_name", serverName)
		if fingerprint := stringValue(source["fp"]); fingerprint != "" {
			tls["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fingerprint}
		}
		outbound["tls"] = tls
	}
	network := strings.ToLower(stringValue(source["net"]))
	if network != "" && network != "tcp" {
		transport := map[string]interface{}{"type": network}
		setMapString(transport, "path", stringValue(source["path"]))
		if host := stringValue(source["host"]); host != "" {
			transport["headers"] = map[string]string{"Host": host}
		}
		outbound["transport"] = transport
	}
	return outbound, nil
}

func convertShadowsocksURI(raw []byte, name string) (Outbound, error) {
	parsed, err := url.Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parse Shadowsocks URI: %w", err)
	}
	var method, password, host, portText string
	if parsed.Hostname() != "" && parsed.User != nil {
		host, portText = parsed.Hostname(), parsed.Port()
		userinfo := parsed.User.Username()
		if decoded, err := decodeFlexibleBase64(userinfo); err == nil {
			userinfo = string(decoded)
		}
		method, password, _ = strings.Cut(userinfo, ":")
		if explicit, exists := parsed.User.Password(); exists {
			password = explicit
		}
	} else {
		payload := strings.TrimPrefix(string(raw), "ss://")
		if marker := strings.IndexAny(payload, "#?"); marker >= 0 {
			payload = payload[:marker]
		}
		decoded, err := decodeFlexibleBase64(payload)
		if err != nil {
			return nil, fmt.Errorf("decode Shadowsocks URI: %w", err)
		}
		credentials, authority, found := strings.Cut(string(decoded), "@")
		if !found {
			return nil, fmt.Errorf("Shadowsocks URI has no authority")
		}
		method, password, found = strings.Cut(credentials, ":")
		if !found {
			return nil, fmt.Errorf("Shadowsocks URI has no method and password")
		}
		host, portText, err = net.SplitHostPort(authority)
		if err != nil {
			return nil, fmt.Errorf("Shadowsocks URI has invalid authority")
		}
	}
	port, err := parsePort(portText)
	if err != nil {
		return nil, err
	}
	return Outbound{
		"type": "shadowsocks", "tag": name, "server": host, "server_port": port,
		"method": method, "password": password,
	}, nil
}

func mapURIType(value string) string {
	switch strings.ToLower(value) {
	case "ss":
		return "shadowsocks"
	case "socks4", "socks4a", "socks5":
		return "socks"
	case "https":
		return "http"
	case "hy2":
		return "hysteria2"
	case "naive+https":
		return "naive"
	case "vless", "trojan", "hysteria2", "tuic", "anytls", "socks", "http", "naive", "hysteria", "wireguard", "ssh":
		return strings.ToLower(value)
	default:
		return ""
	}
}

func uriTLS(query url.Values) map[string]interface{} {
	security := strings.ToLower(query.Get("security"))
	serverName := firstNonEmpty(query.Get("sni"), query.Get("peer"), query.Get("servername"))
	fingerprint := query.Get("fp")
	publicKey := firstNonEmpty(query.Get("pbk"), query.Get("public_key"))
	shortID := firstNonEmpty(query.Get("sid"), query.Get("short_id"))
	if security != "tls" && security != "reality" && serverName == "" && publicKey == "" {
		return nil
	}
	tls := map[string]interface{}{"enabled": true}
	setMapString(tls, "server_name", serverName)
	if insecure, valid := parseBool(firstNonEmpty(query.Get("allowInsecure"), query.Get("insecure"))); valid {
		tls["insecure"] = insecure
	}
	if alpn := splitList(query.Get("alpn")); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if fingerprint != "" {
		tls["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fingerprint}
	}
	if security == "reality" || publicKey != "" {
		if fingerprint == "" {
			tls["utls"] = map[string]interface{}{"enabled": true}
		}
		reality := map[string]interface{}{"enabled": true}
		setMapString(reality, "public_key", publicKey)
		setMapString(reality, "short_id", shortID)
		tls["reality"] = reality
	}
	return tls
}

func uriTransport(query url.Values) map[string]interface{} {
	typeName := strings.ToLower(firstNonEmpty(query.Get("type"), query.Get("network")))
	if typeName == "" || typeName == "tcp" || typeName == "none" {
		return nil
	}
	transport := map[string]interface{}{"type": typeName}
	setMapString(transport, "path", query.Get("path"))
	setMapString(transport, "service_name", firstNonEmpty(query.Get("serviceName"), query.Get("service_name")))
	if host := query.Get("host"); host != "" {
		transport["headers"] = map[string]string{"Host": host}
	}
	return transport
}

func validateURIQuery(values url.Values) error {
	allowed := map[string]struct{}{
		"encryption": {}, "security": {}, "sni": {}, "peer": {}, "servername": {}, "fp": {},
		"pbk": {}, "sid": {}, "public_key": {}, "short_id": {}, "type": {}, "network": {},
		"host": {}, "path": {}, "serviceName": {}, "service_name": {}, "alpn": {}, "flow": {},
		"allowInsecure": {}, "insecure": {}, "headerType": {}, "quicSecurity": {}, "packetEncoding": {}, "packet_encoding": {},
		"mode": {}, "congestion_control": {}, "congestion-controller": {}, "udp_relay_mode": {},
		"udp-relay-mode": {}, "obfs": {}, "obfs-password": {}, "obfs_password": {}, "ports": {}, "mport": {},
		"hop_interval": {}, "hop-interval": {}, "upmbps": {}, "downmbps": {}, "mux": {}, "aid": {}, "scy": {},
	}
	for key := range values {
		if _, known := allowed[key]; !known {
			return fmt.Errorf("URI query parameter %q has no verified sing-box mapping", key)
		}
		if key == "headerType" || key == "quicSecurity" {
			for _, value := range values[key] {
				if value != "" && !strings.EqualFold(value, "none") {
					return fmt.Errorf("URI query parameter %q value has no verified sing-box mapping", key)
				}
			}
		}
	}
	return nil
}

func decodeFlexibleBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	encodings := []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding}
	for _, encoding := range encodings {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("invalid Base64 payload")
}

func stringValue(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}
