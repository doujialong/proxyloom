package aggregate

import (
	"reflect"
	"testing"
)

func TestSelectTemplateNodeTagsRegexOrAll(t *testing.T) {
	tags := []string{"Hong Kong", "Tokyo"}
	selected, marker, err := selectTemplateNodeTags("${PROXYLOOM_NODES_REGEX_OR_ALL:Taiwan}", tags)
	if err != nil || !marker || !reflect.DeepEqual(selected, tags) {
		t.Fatalf("fallback selection = %v, %v, %v", selected, marker, err)
	}

	selected, marker, err = selectTemplateNodeTags("${PROXYLOOM_NODES_REGEX_OR_ALL:Tokyo}", tags)
	if err != nil || !marker || !reflect.DeepEqual(selected, []string{"Tokyo"}) {
		t.Fatalf("matching selection = %v, %v, %v", selected, marker, err)
	}

	manyTags := []string{"One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"}
	selected, marker, err = selectTemplateNodeTags("${PROXYLOOM_NODES_REGEX_OR_FIRST_8:Missing}", manyTags)
	if err != nil || !marker || !reflect.DeepEqual(selected, manyTags[:8]) {
		t.Fatalf("bounded fallback selection = %v, %v, %v", selected, marker, err)
	}
}
