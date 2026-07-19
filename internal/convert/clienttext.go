package convert

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/doujialong/proxyloom/internal/format/clienttext"
)

func ClientTextToSingBox(nodes []clienttext.RawNode, names map[int]string) ([]byte, error) {
	outbounds, err := ClientTextOutbounds(nodes, names)
	if err != nil {
		return nil, err
	}
	return RenderSingBox(outbounds)
}

func ClientTextOutbounds(nodes []clienttext.RawNode, names map[int]string) ([]Outbound, error) {
	outbounds := make([]Outbound, 0, len(nodes)+4)
	for _, node := range nodes {
		name := names[node.Ordinal]
		if name == "" {
			return nil, fmt.Errorf("client node %d has no allocated output name", node.Ordinal)
		}
		converted, err := convertClientNode(node, name)
		if err != nil {
			return nil, fmt.Errorf("convert client node %d (%s): %w", node.Ordinal, node.ProtocolID, err)
		}
		outbounds = append(outbounds, converted...)
	}
	return outbounds, nil
}

func convertClientNode(node clienttext.RawNode, name string) ([]Outbound, error) {
	fields, err := splitClientCSV(string(node.Raw))
	if err != nil {
		return nil, err
	}
	if node.Style == clienttext.StyleNamedAssignment {
		if len(fields) == 0 {
			return nil, fmt.Errorf("named proxy assignment is empty")
		}
		_, right, found := strings.Cut(fields[0], "=")
		if !found {
			return nil, fmt.Errorf("named proxy assignment has no equals sign")
		}
		fields[0] = right
		return convertClientFields(node, name, fields, false)
	}
	return convertClientFields(node, name, fields, true)
}

func convertClientFields(node clienttext.RawNode, name string, fields []string, quantumultX bool) ([]Outbound, error) {
	if len(fields) < 1 {
		return nil, fmt.Errorf("client proxy has no fields")
	}
	values := make(map[string]string)
	positionals := make([]string, 0, len(fields))
	server := ""
	portText := ""
	if quantumultX {
		typeName, authority, found := strings.Cut(strings.TrimSpace(fields[0]), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(typeName), node.RawType) {
			return nil, fmt.Errorf("Quantumult X proxy type differs from parsed metadata")
		}
		host, port, err := splitAuthority(strings.TrimSpace(authority))
		if err != nil {
			return nil, err
		}
		server, portText = host, port
		for _, field := range fields[1:] {
			key, value, found := strings.Cut(field, "=")
			if !found {
				return nil, fmt.Errorf("Quantumult X positional field has no verified mapping")
			}
			values[strings.ToLower(strings.TrimSpace(key))] = unquoteClient(strings.TrimSpace(value))
		}
	} else {
		if len(fields) < 3 {
			return nil, fmt.Errorf("client proxy requires type, server and port")
		}
		positionals = append(positionals, strings.TrimSpace(fields[1]), strings.TrimSpace(fields[2]))
		server, portText = positionals[0], positionals[1]
		for _, field := range fields[3:] {
			key, value, found := strings.Cut(field, "=")
			if found {
				values[strings.ToLower(strings.TrimSpace(key))] = unquoteClient(strings.TrimSpace(value))
			} else {
				positionals = append(positionals, unquoteClient(strings.TrimSpace(field)))
			}
		}
	}
	if err := validateClientKeys(values); err != nil {
		return nil, err
	}
	port, err := parsePort(portText)
	if err != nil {
		return nil, err
	}
	typeName := mapClientType(node.RawType)
	if typeName == "" {
		return nil, fmt.Errorf("client protocol %q cannot be represented by sing-box", node.RawType)
	}
	outbound := Outbound{"type": typeName, "tag": name, "server": server, "server_port": port}
	pos := func(index int) string {
		actual := index + 2
		if actual >= 0 && actual < len(positionals) {
			return positionals[actual]
		}
		return ""
	}
	credential := func(key string, positional int) string {
		if value := values[key]; value != "" {
			return value
		}
		return pos(positional)
	}
	switch typeName {
	case "shadowsocks":
		setString(outbound, "method", firstNonEmpty(values["encrypt-method"], values["method"], credential("cipher", 0)))
		setString(outbound, "password", credential("password", 1))
	case "vmess":
		if values["username"] != "" {
			setString(outbound, "uuid", values["username"])
		} else if quantumultX {
			setString(outbound, "uuid", values["password"])
		} else {
			setString(outbound, "uuid", pos(1))
			setString(outbound, "security", pos(0))
		}
		if values["method"] != "" && values["method"] != "none" {
			setString(outbound, "security", values["method"])
		}
		if alterID, err := strconv.Atoi(values["alterid"]); err == nil {
			outbound["alter_id"] = alterID
		}
	case "vless":
		if quantumultX {
			setString(outbound, "uuid", values["password"])
		} else {
			setString(outbound, "uuid", pos(0))
		}
		setString(outbound, "flow", firstNonEmpty(values["vless-flow"], values["flow"]))
	case "hysteria2":
		setString(outbound, "password", credential("password", 0))
		if rawPorts := splitList(firstNonEmpty(values["port-hopping"], values["ports"])); len(rawPorts) > 0 {
			ports, err := normalizeHysteria2ServerPorts(rawPorts)
			if err != nil {
				return nil, err
			}
			outbound["server_ports"] = ports
		}
		setString(outbound, "hop_interval", normalizeSecondDuration(firstNonEmpty(values["port-hopping-interval"], values["hop-interval"])))
		if salamander := values["salamander-password"]; salamander != "" {
			outbound["obfs"] = map[string]interface{}{"type": "salamander", "password": salamander}
		}
	case "anytls", "trojan":
		setString(outbound, "password", credential("password", 0))
	case "tuic":
		setString(outbound, "uuid", firstNonEmpty(values["uuid"], pos(0)))
		setString(outbound, "password", firstNonEmpty(values["password"], pos(1)))
		setString(outbound, "congestion_control", values["congestion-controller"])
		setString(outbound, "udp_relay_mode", values["udp-relay-mode"])
	}
	if fastOpen, valid := parseBool(values["fast-open"]); valid {
		outbound["tcp_fast_open"] = fastOpen
	}
	if udp, valid := parseBool(firstNonEmpty(values["udp-relay"], values["udp"])); valid && !udp {
		outbound["network"] = "tcp"
	}
	if tls := clientTLS(values); tls != nil {
		outbound["tls"] = tls
	}
	if transport := clientTransport(values); transport != nil {
		outbound["transport"] = transport
	}
	if typeName == "shadowsocks" && values["shadow-tls-password"] != "" {
		transportTag := fmt.Sprintf("__proxyloom_shadowtls_%d", node.Ordinal+1)
		shadowTLS := Outbound{
			"type": "shadowtls", "tag": transportTag, "server": server, "server_port": port,
			"password": values["shadow-tls-password"],
		}
		if version, err := strconv.Atoi(values["shadow-tls-version"]); err == nil {
			shadowTLS["version"] = version
		}
		if sni := values["shadow-tls-sni"]; sni != "" {
			shadowTLS["tls"] = map[string]interface{}{"enabled": true, "server_name": sni}
		}
		outbound["detour"] = transportTag
		return []Outbound{shadowTLS, outbound}, nil
	}
	return []Outbound{outbound}, nil
}

func mapClientType(value string) string {
	switch strings.ToLower(value) {
	case "ss", "shadowsocks":
		return "shadowsocks"
	case "socks5", "socks":
		return "socks"
	case "https":
		return "http"
	case "hy2":
		return "hysteria2"
	case "vmess", "vless", "trojan", "hysteria2", "anytls", "tuic", "http":
		return strings.ToLower(value)
	default:
		return ""
	}
}

func clientTLS(values map[string]string) map[string]interface{} {
	enabled := false
	present := false
	for _, key := range []string{"over-tls", "tls"} {
		if value, valid := parseBool(values[key]); valid {
			enabled, present = enabled || value, true
		}
	}
	obfs := strings.ToLower(values["obfs"])
	if obfs == "wss" || obfs == "over-tls" {
		enabled, present = true, true
	}
	serverName := firstNonEmpty(values["sni"], values["tls-name"], values["tls-host"], values["obfs-host"])
	publicKey := values["reality-base64-pubkey"]
	shortID := values["reality-hex-shortid"]
	if serverName != "" || publicKey != "" {
		enabled, present = true, true
	}
	if !present {
		return nil
	}
	tls := map[string]interface{}{"enabled": enabled}
	setMapString(tls, "server_name", serverName)
	if insecure, valid := parseBool(values["skip-cert-verify"]); valid {
		tls["insecure"] = insecure
	} else if verify, valid := parseBool(values["tls-verification"]); valid {
		tls["insecure"] = !verify
	}
	if alpn := normalizeClientALPN(splitList(values["alpn"])); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if publicKey != "" {
		tls["utls"] = map[string]interface{}{"enabled": true}
		reality := map[string]interface{}{"enabled": true, "public_key": publicKey}
		setMapString(reality, "short_id", shortID)
		tls["reality"] = reality
	}
	return tls
}

func normalizeClientALPN(values []string) []string {
	for index, value := range values {
		switch strings.ToLower(value) {
		case "http1.1", "http/1.1":
			values[index] = "http/1.1"
		}
	}
	return values
}

func clientTransport(values map[string]string) map[string]interface{} {
	typeName := strings.ToLower(firstNonEmpty(values["transport"], values["obfs"]))
	if ws, valid := parseBool(values["ws"]); valid && ws {
		typeName = "ws"
	}
	if typeName == "wss" {
		typeName = "ws"
	}
	if typeName == "" || typeName == "none" || typeName == "tcp" || typeName == "over-tls" {
		return nil
	}
	transport := map[string]interface{}{"type": typeName}
	setMapString(transport, "path", firstNonEmpty(values["path"], values["ws-path"], values["obfs-uri"]))
	host := firstNonEmpty(values["host"], values["obfs-host"], clientHeaderHost(values["ws-headers"]))
	if host != "" {
		transport["headers"] = map[string]string{"Host": host}
	}
	return transport
}

func validateClientKeys(values map[string]string) error {
	allowed := map[string]struct{}{
		"password": {}, "sni": {}, "udp-relay": {}, "port-hopping": {}, "port-hopping-interval": {},
		"download-bandwidth": {}, "upload-bandwidth": {}, "salamander-password": {}, "encrypt-method": {},
		"shadow-tls-password": {}, "shadow-tls-version": {}, "shadow-tls-sni": {}, "username": {},
		"vmess-aead": {}, "tls": {}, "ws": {}, "ws-path": {}, "ws-headers": {}, "method": {},
		"fast-open": {}, "obfs": {}, "obfs-host": {}, "obfs-uri": {}, "tag": {}, "aead": {},
		"reality-base64-pubkey": {}, "reality-hex-shortid": {}, "vless-flow": {}, "flow": {},
		"over-tls": {}, "tls-host": {}, "transport": {}, "path": {}, "host": {}, "tls-name": {},
		"skip-cert-verify": {}, "udp": {}, "alterid": {}, "cipher": {}, "uuid": {},
		"alpn": {}, "tls-verification": {},
		"congestion-controller": {}, "udp-relay-mode": {}, "ports": {}, "hop-interval": {},
	}
	for key := range values {
		if _, known := allowed[key]; !known {
			return fmt.Errorf("client field %q has no verified sing-box mapping", key)
		}
	}
	return nil
}

func splitClientCSV(value string) ([]string, error) {
	result := make([]string, 0, 16)
	start := 0
	quote := byte(0)
	escaped := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' && quote != 0 {
			escaped = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if character == ',' {
			result = append(result, strings.TrimSpace(value[start:index]))
			start = index + 1
		}
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("client proxy contains an unterminated quoted field")
	}
	return append(result, strings.TrimSpace(value[start:])), nil
}

func splitAuthority(value string) (string, string, error) {
	if strings.HasPrefix(value, "[") {
		host, port, err := net.SplitHostPort(value)
		return host, port, err
	}
	index := strings.LastIndexByte(value, ':')
	if index <= 0 || index == len(value)-1 {
		return "", "", fmt.Errorf("client proxy has an invalid server authority")
	}
	return value[:index], value[index+1:], nil
}

func unquoteClient(value string) string {
	if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'') {
		return value[1 : len(value)-1]
	}
	return value
}

func clientHeaderHost(value string) string {
	for _, separator := range []string{":", "="} {
		key, content, found := strings.Cut(value, separator)
		if found && strings.EqualFold(strings.TrimSpace(key), "host") {
			return strings.TrimSpace(content)
		}
	}
	return ""
}
