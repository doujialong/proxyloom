package singbox

import "encoding/json"

// ContainsECH reports whether a node document contains an ECH TLS configuration.
func ContainsECH(content []byte) bool {
	var value interface{}
	if len(content) == 0 || json.Unmarshal(content, &value) != nil {
		return false
	}
	return containsECHValue(value)
}

func containsECHValue(value interface{}) bool {
	switch typed := value.(type) {
	case map[string]interface{}:
		if tls, ok := typed["tls"].(map[string]interface{}); ok {
			if ech, exists := tls["ech"]; exists && ech != nil {
				return true
			}
		}
		for _, child := range typed {
			if containsECHValue(child) {
				return true
			}
		}
	case []interface{}:
		for _, child := range typed {
			if containsECHValue(child) {
				return true
			}
		}
	}
	return false
}
