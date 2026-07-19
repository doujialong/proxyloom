package jsonlossless

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

func MarshalCompact(node *Node) ([]byte, error) {
	var output bytes.Buffer
	if err := appendCompact(&output, node); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func MarshalIndent(node *Node, prefix, indent string) ([]byte, error) {
	var output bytes.Buffer
	if err := appendIndent(&output, node, prefix, indent, 0); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// MarshalOpaqueV1 encodes a stable fingerprint projection. Object keys are
// sorted by their decoded UTF-8 value, arrays retain order, and number lexemes
// are never converted. excludeRootMember applies only to the root object.
func MarshalOpaqueV1(node *Node, excludeRootMember string) ([]byte, error) {
	var output bytes.Buffer
	if err := appendCanonical(&output, node, excludeRootMember, true); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func appendCompact(output *bytes.Buffer, node *Node) error {
	if node == nil {
		return fmt.Errorf("nil JSON node")
	}
	switch node.Kind {
	case KindNull, KindBool, KindNumber, KindString:
		output.WriteString(node.Raw)
	case KindArray:
		output.WriteByte('[')
		for i, element := range node.Elements {
			if i > 0 {
				output.WriteByte(',')
			}
			if err := appendCompact(output, element); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case KindObject:
		output.WriteByte('{')
		for i, member := range node.Members {
			if i > 0 {
				output.WriteByte(',')
			}
			output.WriteString(memberKeyRaw(member))
			output.WriteByte(':')
			if err := appendCompact(output, member.Value); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("invalid JSON kind %d", node.Kind)
	}
	return nil
}

func appendIndent(output *bytes.Buffer, node *Node, prefix, indent string, depth int) error {
	if node == nil {
		return fmt.Errorf("nil JSON node")
	}
	switch node.Kind {
	case KindNull, KindBool, KindNumber, KindString:
		output.WriteString(node.Raw)
	case KindArray:
		if len(node.Elements) == 0 {
			output.WriteString("[]")
			return nil
		}
		output.WriteString("[\n")
		for i, element := range node.Elements {
			writeIndent(output, prefix, indent, depth+1)
			if err := appendIndent(output, element, prefix, indent, depth+1); err != nil {
				return err
			}
			if i+1 < len(node.Elements) {
				output.WriteByte(',')
			}
			output.WriteByte('\n')
		}
		writeIndent(output, prefix, indent, depth)
		output.WriteByte(']')
	case KindObject:
		if len(node.Members) == 0 {
			output.WriteString("{}")
			return nil
		}
		output.WriteString("{\n")
		for i, member := range node.Members {
			writeIndent(output, prefix, indent, depth+1)
			output.WriteString(memberKeyRaw(member))
			output.WriteString(": ")
			if err := appendIndent(output, member.Value, prefix, indent, depth+1); err != nil {
				return err
			}
			if i+1 < len(node.Members) {
				output.WriteByte(',')
			}
			output.WriteByte('\n')
		}
		writeIndent(output, prefix, indent, depth)
		output.WriteByte('}')
	default:
		return fmt.Errorf("invalid JSON kind %d", node.Kind)
	}
	return nil
}

func appendCanonical(output *bytes.Buffer, node *Node, excluded string, root bool) error {
	if node == nil {
		return fmt.Errorf("nil JSON node")
	}
	switch node.Kind {
	case KindNull, KindBool, KindNumber:
		output.WriteString(node.Raw)
	case KindString:
		encoded, _ := json.Marshal(node.String)
		output.Write(encoded)
	case KindArray:
		output.WriteByte('[')
		for i, element := range node.Elements {
			if i > 0 {
				output.WriteByte(',')
			}
			if err := appendCanonical(output, element, excluded, false); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case KindObject:
		members := make([]Member, 0, len(node.Members))
		for _, member := range node.Members {
			if root && member.Key == excluded {
				continue
			}
			members = append(members, member)
		}
		sort.SliceStable(members, func(i, j int) bool {
			return members[i].Key < members[j].Key
		})
		output.WriteByte('{')
		for i, member := range members {
			if i > 0 {
				output.WriteByte(',')
			}
			key, _ := json.Marshal(member.Key)
			output.Write(key)
			output.WriteByte(':')
			if err := appendCanonical(output, member.Value, excluded, false); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("invalid JSON kind %d", node.Kind)
	}
	return nil
}

func memberKeyRaw(member Member) string {
	if member.KeyRaw != "" {
		return member.KeyRaw
	}
	encoded, _ := json.Marshal(member.Key)
	return string(encoded)
}

func writeIndent(output *bytes.Buffer, prefix, indent string, depth int) {
	output.WriteString(prefix)
	for i := 0; i < depth; i++ {
		output.WriteString(indent)
	}
}
