package aggregate

import (
	"testing"

	"github.com/doujialong/proxyloom/internal/storage/outputstore"
)

func TestCompositePipelineFilterMatchesAllConditions(t *testing.T) {
	config := map[string]interface{}{
		"all": []interface{}{
			map[string]interface{}{"field": "source_id", "operator": "equals", "value": "source-a"},
			map[string]interface{}{"field": "protocol", "operator": "equals", "value": "hysteria2"},
		},
	}
	if err := validateFilterConfig(config); err != nil {
		t.Fatalf("validate composite filter: %v", err)
	}
	matched, err := matchesFilter(candidate{input: outputstore.NodeInput{SourceID: "source-a", ProtocolID: "hysteria2"}}, config)
	if err != nil || !matched {
		t.Fatalf("matching candidate: matched=%v err=%v", matched, err)
	}
	matched, err = matchesFilter(candidate{input: outputstore.NodeInput{SourceID: "source-b", ProtocolID: "hysteria2"}}, config)
	if err != nil || matched {
		t.Fatalf("different source candidate: matched=%v err=%v", matched, err)
	}
}

func TestCompositePipelineFilterRejectsNestedAndOversizedGroups(t *testing.T) {
	nested := map[string]interface{}{"all": []interface{}{map[string]interface{}{"any": []interface{}{}}}}
	if err := validateFilterConfig(nested); err == nil {
		t.Fatal("nested filter group was accepted")
	}
	conditions := make([]interface{}, 17)
	for index := range conditions {
		conditions[index] = map[string]interface{}{"field": "protocol", "operator": "equals", "value": "hysteria2"}
	}
	if err := validateFilterConfig(map[string]interface{}{"any": conditions}); err == nil {
		t.Fatal("oversized filter group was accepted")
	}
}
