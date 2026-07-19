package outputstore

import "testing"

func TestValidatePipelineConfigAcceptsUserEditableOperations(t *testing.T) {
	valid := PipelineConfig{Operations: []Operation{
		{Type: "filter", SchemaVersion: 1, Config: map[string]interface{}{"field": "name", "operator": "contains", "value": "expired"}},
		{Type: "rename", SchemaVersion: 1, Config: map[string]interface{}{"suffix": " test"}},
		{Type: "sort", SchemaVersion: 1, Config: map[string]interface{}{"by": "name"}},
	}}
	if err := validatePipelineConfig(valid); err != nil {
		t.Fatalf("valid editable pipeline rejected: %v", err)
	}
	invalid := valid
	invalid.Operations = append(invalid.Operations, Operation{Type: "execute", SchemaVersion: 1})
	if err := validatePipelineConfig(invalid); err == nil {
		t.Fatal("unsupported pipeline operation was accepted")
	}
}
