package patch

import (
	"testing"

	"github.com/doujialong/proxyloom/internal/jsonlossless"
)

func TestApplyTagChangesOnlyTag(t *testing.T) {
	raw, err := jsonlossless.Parse([]byte(`{"type":"vless","tag":"old","tls":{"ech":{"enabled":true}},"number":1.2300}`), jsonlossless.DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	patched, change, err := ApplyTag(raw, "old #2", "name-conflict")
	if err != nil {
		t.Fatalf("ApplyTag() error = %v", err)
	}
	if change == nil || change.Path != "/tag" || change.Operation != OperationReplace {
		t.Fatalf("change = %+v", change)
	}
	output, _ := jsonlossless.MarshalCompact(patched)
	want := `{"type":"vless","tag":"old #2","tls":{"ech":{"enabled":true}},"number":1.2300}`
	if string(output) != want {
		t.Fatalf("patched\nwant: %s\n got: %s", want, output)
	}
	original, _ := jsonlossless.MarshalCompact(raw)
	if string(original) == string(output) {
		t.Fatal("original and patched unexpectedly match")
	}
}
