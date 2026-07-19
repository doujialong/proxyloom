package patch

import (
	"fmt"

	"github.com/doujialong/proxyloom/internal/jsonlossless"
)

const EngineVersion = "singbox-tag-patch-v1"

type Operation string

const (
	OperationAdd     Operation = "add"
	OperationReplace Operation = "replace"
)

type Change struct {
	Operation Operation
	Path      string
	Previous  string
	Value     string
	Origin    string
}

func ApplyTag(raw *jsonlossless.Node, tag, origin string) (*jsonlossless.Node, *Change, error) {
	if raw == nil || raw.Kind != jsonlossless.KindObject {
		return nil, nil, fmt.Errorf("tag patch requires an object")
	}
	if tag == "" {
		return nil, nil, fmt.Errorf("tag patch requires a non-empty value")
	}

	clone := raw.Clone()
	previousNode, existed := clone.Member("tag")
	previous, validPrevious := previousNode.StringValue()
	if existed && !validPrevious {
		return nil, nil, fmt.Errorf("existing tag is not a string")
	}
	if existed && previous == tag {
		return clone, nil, nil
	}
	if _, _, err := clone.SetStringMember("tag", tag); err != nil {
		return nil, nil, err
	}
	operation := OperationAdd
	if existed {
		operation = OperationReplace
	}
	return clone, &Change{
		Operation: operation,
		Path:      "/tag",
		Previous:  previous,
		Value:     tag,
		Origin:    origin,
	}, nil
}
