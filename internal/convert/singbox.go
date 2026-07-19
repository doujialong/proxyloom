package convert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const SingBoxRendererVersion = "sing-box-cross-format-v1"

type Outbound map[string]interface{}

func RenderSingBox(outbounds []Outbound) ([]byte, error) {
	if len(outbounds) == 0 {
		return nil, fmt.Errorf("sing-box output requires at least one converted outbound")
	}
	seen := make(map[string]struct{}, len(outbounds))
	for index, outbound := range outbounds {
		tag, _ := outbound["tag"].(string)
		typeName, _ := outbound["type"].(string)
		if tag == "" || typeName == "" {
			return nil, fmt.Errorf("converted outbound %d is missing type or tag", index)
		}
		if _, duplicate := seen[tag]; duplicate {
			return nil, fmt.Errorf("converted sing-box outbound tag %q is duplicated", tag)
		}
		seen[tag] = struct{}{}
		if err := validateConvertedOutbound(outbound); err != nil {
			return nil, fmt.Errorf("converted outbound %q: %w", tag, err)
		}
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]interface{}{"outbounds": outbounds}); err != nil {
		return nil, fmt.Errorf("encode sing-box output: %w", err)
	}
	return output.Bytes(), nil
}

func validateConvertedOutbound(outbound Outbound) error {
	typeName, _ := outbound["type"].(string)
	for _, name := range []string{"server"} {
		if value, _ := outbound[name].(string); strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	port, valid := outbound["server_port"].(int)
	if !valid || port < 1 || port > 65535 {
		return fmt.Errorf("server_port is required and must be between 1 and 65535")
	}
	requireString := func(name string) error {
		if value, _ := outbound[name].(string); value == "" {
			return fmt.Errorf("%s is required for %s", name, typeName)
		}
		return nil
	}
	switch typeName {
	case "shadowsocks":
		if err := requireString("method"); err != nil {
			return err
		}
		return requireString("password")
	case "vmess", "vless":
		return requireString("uuid")
	case "trojan", "hysteria2", "anytls", "shadowtls":
		return requireString("password")
	case "tuic":
		if err := requireString("uuid"); err != nil {
			return err
		}
		return requireString("password")
	case "socks", "http", "hysteria", "wireguard", "ssh", "naive":
		return nil
	default:
		return fmt.Errorf("protocol %q is not supported by the sing-box cross-format renderer", typeName)
	}
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid server port")
	}
	return port, nil
}

func parseBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on", "enabled":
		return true, true
	case "false", "0", "no", "off", "disabled":
		return false, true
	default:
		return false, false
	}
}

func splitList(value string) []string {
	parts := strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || character == ';' || character == '|'
	})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func normalizeHysteria2ServerPorts(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		startText, endText, found := strings.Cut(value, ":")
		if !found {
			startText, endText, found = strings.Cut(value, "-")
		}
		if !found {
			startText, endText = value, value
		}
		start, startErr := parsePort(startText)
		end, endErr := parsePort(endText)
		if startErr != nil || endErr != nil || start > end {
			return nil, fmt.Errorf("invalid Hysteria2 server port range %q", value)
		}
		result = append(result, fmt.Sprintf("%d:%d", start, end))
	}
	return result, nil
}

func normalizeSecondDuration(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if _, err := strconv.ParseUint(value, 10, 64); err == nil {
		return value + "s"
	}
	return value
}

func setString(target Outbound, key, value string) {
	if value = strings.TrimSpace(value); value != "" {
		target[key] = value
	}
}
