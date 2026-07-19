package jsonlossless

import (
	"encoding/json"
	"fmt"
)

const ASTVersion = "ordered-json-v1"

// Kind identifies a JSON value without converting numbers to floating point.
type Kind uint8

const (
	KindNull Kind = iota
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
)

// Member retains both the decoded key and its original JSON representation.
type Member struct {
	Key    string
	KeyRaw string
	Value  *Node
}

// Node is an ordered JSON AST. Raw contains the validated lexical form for
// primitive values, while object and array order is retained in slices.
type Node struct {
	Kind     Kind
	Raw      string
	String   string
	Members  []Member
	Elements []*Node
}

func NewObject(members ...Member) *Node {
	return &Node{Kind: KindObject, Members: members}
}

func NewArray(elements ...*Node) *Node {
	return &Node{Kind: KindArray, Elements: elements}
}

func NewString(value string) *Node {
	raw, _ := json.Marshal(value)
	return &Node{Kind: KindString, Raw: string(raw), String: value}
}

func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}

	clone := &Node{
		Kind:   n.Kind,
		Raw:    n.Raw,
		String: n.String,
	}
	if len(n.Members) > 0 {
		clone.Members = make([]Member, len(n.Members))
		for i, member := range n.Members {
			clone.Members[i] = Member{
				Key:    member.Key,
				KeyRaw: member.KeyRaw,
				Value:  member.Value.Clone(),
			}
		}
	}
	if len(n.Elements) > 0 {
		clone.Elements = make([]*Node, len(n.Elements))
		for i, element := range n.Elements {
			clone.Elements[i] = element.Clone()
		}
	}
	return clone
}

func (n *Node) Member(name string) (*Node, bool) {
	if n == nil || n.Kind != KindObject {
		return nil, false
	}
	for _, member := range n.Members {
		if member.Key == name {
			return member.Value, true
		}
	}
	return nil, false
}

func (n *Node) MemberIndex(name string) int {
	if n == nil || n.Kind != KindObject {
		return -1
	}
	for i, member := range n.Members {
		if member.Key == name {
			return i
		}
	}
	return -1
}

func (n *Node) RemoveMember(name string) bool {
	index := n.MemberIndex(name)
	if index < 0 {
		return false
	}
	n.Members = append(n.Members[:index], n.Members[index+1:]...)
	return true
}

// SetStringMember replaces a member in place or appends it when absent.
func (n *Node) SetStringMember(name, value string) (previous *Node, existed bool, err error) {
	if n == nil || n.Kind != KindObject {
		return nil, false, fmt.Errorf("set member on non-object")
	}

	replacement := NewString(value)
	index := n.MemberIndex(name)
	if index >= 0 {
		previous = n.Members[index].Value
		n.Members[index].Value = replacement
		return previous, true, nil
	}

	keyRaw, _ := json.Marshal(name)
	n.Members = append(n.Members, Member{
		Key:    name,
		KeyRaw: string(keyRaw),
		Value:  replacement,
	})
	return nil, false, nil
}

func (n *Node) StringValue() (string, bool) {
	if n == nil || n.Kind != KindString {
		return "", false
	}
	return n.String, true
}

func (n *Node) NumberLexeme() (string, bool) {
	if n == nil || n.Kind != KindNumber {
		return "", false
	}
	return n.Raw, true
}

func (n *Node) BoolValue() (bool, bool) {
	if n == nil || n.Kind != KindBool {
		return false, false
	}
	return n.Raw == "true", true
}
