package convert

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/doujialong/proxyloom/internal/format/mihomo"
	"gopkg.in/yaml.v3"
)

func MihomoToSingBox(nodes []mihomo.RawNode, names map[int]string) ([]byte, error) {
	outbounds, err := MihomoOutbounds(nodes, names)
	if err != nil {
		return nil, err
	}
	return RenderSingBox(outbounds)
}

func MihomoOutbounds(nodes []mihomo.RawNode, names map[int]string) ([]Outbound, error) {
	outbounds := make([]Outbound, 0, len(nodes))
	for _, node := range nodes {
		name := names[node.Ordinal]
		if name == "" {
			return nil, fmt.Errorf("Mihomo node %d has no allocated output name", node.Ordinal)
		}
		outbound, err := convertMihomoNode(node, name)
		if err != nil {
			return nil, fmt.Errorf("convert Mihomo node %d (%s): %w", node.Ordinal, node.ProtocolID, err)
		}
		outbounds = append(outbounds, outbound)
	}
	return outbounds, nil
}

func convertMihomoNode(node mihomo.RawNode, name string) (Outbound, error) {
	if node.Raw == nil || node.Raw.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("proxy is not a YAML mapping")
	}
	allowed := map[string]struct{}{
		"name": {}, "type": {}, "server": {}, "port": {}, "password": {}, "uuid": {},
		"cipher": {}, "alterId": {}, "flow": {}, "network": {}, "tls": {}, "servername": {},
		"sni": {}, "skip-cert-verify": {}, "client-fingerprint": {}, "alpn": {}, "ws-opts": {},
		"reality-opts": {}, "congestion-controller": {}, "udp-relay-mode": {}, "ports": {},
		"hop-interval": {}, "obfs": {}, "obfs-password": {}, "udp": {},
	}
	for index := 0; index+1 < len(node.Raw.Content); index += 2 {
		key := node.Raw.Content[index].Value
		if _, known := allowed[key]; !known {
			return nil, fmt.Errorf("field %q has no verified sing-box mapping", key)
		}
	}
	typeName := mapMihomoType(node.RawType)
	if typeName == "" {
		return nil, fmt.Errorf("protocol type %q cannot be represented by sing-box", node.RawType)
	}
	server, _ := yamlString(node.Raw, "server")
	portText, _ := yamlString(node.Raw, "port")
	port, err := parsePort(portText)
	if err != nil {
		return nil, err
	}
	outbound := Outbound{"type": typeName, "tag": name, "server": server, "server_port": port}
	switch typeName {
	case "shadowsocks":
		setString(outbound, "method", yamlStringValue(node.Raw, "cipher"))
		setString(outbound, "password", yamlStringValue(node.Raw, "password"))
	case "vmess":
		setString(outbound, "uuid", yamlStringValue(node.Raw, "uuid"))
		setString(outbound, "security", yamlStringValue(node.Raw, "cipher"))
		if alterID, ok := yamlInt(node.Raw, "alterId"); ok {
			outbound["alter_id"] = alterID
		}
	case "vless":
		setString(outbound, "uuid", yamlStringValue(node.Raw, "uuid"))
		setString(outbound, "flow", yamlStringValue(node.Raw, "flow"))
	case "trojan", "hysteria2", "anytls":
		setString(outbound, "password", yamlStringValue(node.Raw, "password"))
	case "tuic":
		setString(outbound, "uuid", yamlStringValue(node.Raw, "uuid"))
		setString(outbound, "password", yamlStringValue(node.Raw, "password"))
		setString(outbound, "congestion_control", yamlStringValue(node.Raw, "congestion-controller"))
		setString(outbound, "udp_relay_mode", yamlStringValue(node.Raw, "udp-relay-mode"))
	}
	if typeName == "hysteria2" {
		rawPorts := yamlStringList(node.Raw, "ports")
		if len(rawPorts) > 0 {
			ports, err := normalizeHysteria2ServerPorts(rawPorts)
			if err != nil {
				return nil, err
			}
			outbound["server_ports"] = ports
		}
		setString(outbound, "hop_interval", normalizeSecondDuration(yamlStringValue(node.Raw, "hop-interval")))
		obfsType := yamlStringValue(node.Raw, "obfs")
		obfsPassword := yamlStringValue(node.Raw, "obfs-password")
		if obfsType != "" || obfsPassword != "" {
			outbound["obfs"] = map[string]interface{}{"type": obfsType, "password": obfsPassword}
		}
	}
	if tls := mihomoTLS(node.Raw); tls != nil {
		outbound["tls"] = tls
	}
	if transport := mihomoTransport(node.Raw); transport != nil {
		outbound["transport"] = transport
	}
	return outbound, nil
}

func mapMihomoType(value string) string {
	switch strings.ToLower(value) {
	case "ss":
		return "shadowsocks"
	case "socks5":
		return "socks"
	case "hysteria2", "hy2":
		return "hysteria2"
	case "vmess", "vless", "trojan", "tuic", "anytls", "http", "hysteria", "wireguard", "ssh":
		return strings.ToLower(value)
	default:
		return ""
	}
}

func mihomoTLS(node *yaml.Node) map[string]interface{} {
	enabled, hasTLS := yamlBool(node, "tls")
	serverName := firstNonEmpty(yamlStringValue(node, "sni"), yamlStringValue(node, "servername"))
	insecure, hasInsecure := yamlBool(node, "skip-cert-verify")
	fingerprint := yamlStringValue(node, "client-fingerprint")
	reality, hasReality := yamlMapping(node, "reality-opts")
	if !hasTLS && serverName == "" && !hasInsecure && fingerprint == "" && !hasReality {
		return nil
	}
	if !hasTLS {
		enabled = true
	}
	tls := map[string]interface{}{"enabled": enabled}
	if serverName != "" {
		tls["server_name"] = serverName
	}
	if hasInsecure {
		tls["insecure"] = insecure
	}
	if alpn := yamlStringList(node, "alpn"); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if fingerprint != "" {
		tls["utls"] = map[string]interface{}{"enabled": true, "fingerprint": fingerprint}
	}
	if hasReality {
		if fingerprint == "" {
			tls["utls"] = map[string]interface{}{"enabled": true}
		}
		options := map[string]interface{}{"enabled": true}
		setMapString(options, "public_key", yamlStringValue(reality, "public-key"))
		setMapString(options, "short_id", yamlStringValue(reality, "short-id"))
		tls["reality"] = options
	}
	return tls
}

func mihomoTransport(node *yaml.Node) map[string]interface{} {
	network := strings.ToLower(yamlStringValue(node, "network"))
	if network == "" || network == "tcp" {
		return nil
	}
	transport := map[string]interface{}{"type": network}
	if network == "ws" {
		if ws, ok := yamlMapping(node, "ws-opts"); ok {
			setMapString(transport, "path", yamlStringValue(ws, "path"))
			if headers, ok := yamlMapping(ws, "headers"); ok {
				converted := make(map[string]string)
				for index := 0; index+1 < len(headers.Content); index += 2 {
					converted[headers.Content[index].Value] = headers.Content[index+1].Value
				}
				if len(converted) > 0 {
					transport["headers"] = converted
				}
			}
		}
	}
	return transport
}

func yamlMapping(node *yaml.Node, key string) (*yaml.Node, bool) {
	value, exists := yamlValue(node, key)
	return value, exists && value.Kind == yaml.MappingNode
}

func yamlValue(node *yaml.Node, key string) (*yaml.Node, bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, false
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1], true
		}
	}
	return nil, false
}

func yamlString(node *yaml.Node, key string) (string, bool) {
	value, exists := yamlValue(node, key)
	if !exists || value.Kind != yaml.ScalarNode {
		return "", false
	}
	return strings.TrimSpace(value.Value), true
}

func yamlStringValue(node *yaml.Node, key string) string {
	value, _ := yamlString(node, key)
	return value
}

func yamlInt(node *yaml.Node, key string) (int, bool) {
	value, exists := yamlString(node, key)
	if !exists {
		return 0, false
	}
	parsed, err := strconv.Atoi(value)
	return parsed, err == nil
}

func yamlBool(node *yaml.Node, key string) (bool, bool) {
	value, exists := yamlString(node, key)
	if !exists {
		return false, false
	}
	parsed, valid := parseBool(value)
	return parsed, valid
}

func yamlStringList(node *yaml.Node, key string) []string {
	value, exists := yamlValue(node, key)
	if !exists {
		return nil
	}
	if value.Kind == yaml.SequenceNode {
		result := make([]string, 0, len(value.Content))
		for _, child := range value.Content {
			if child.Kind == yaml.ScalarNode && strings.TrimSpace(child.Value) != "" {
				result = append(result, strings.TrimSpace(child.Value))
			}
		}
		return result
	}
	if value.Kind == yaml.ScalarNode {
		return splitList(value.Value)
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func setMapString(target map[string]interface{}, key, value string) {
	if value = strings.TrimSpace(value); value != "" {
		target[key] = value
	}
}
