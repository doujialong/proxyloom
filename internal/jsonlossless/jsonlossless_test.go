package jsonlossless

import (
	"errors"
	"strings"
	"testing"
)

func TestRoundTripPreservesOrderAndLexemes(t *testing.T) {
	input := []byte(`{"z":900719925474099312345,"ratio":1.2300,"power":1E+09,"escaped":"a\u0062","nested":{"b":2,"a":1}}`)
	node, err := Parse(input, DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	compact, err := MarshalCompact(node)
	if err != nil {
		t.Fatalf("MarshalCompact() error = %v", err)
	}
	if string(compact) != string(input) {
		t.Fatalf("round trip changed lexemes\nwant: %s\n got: %s", input, compact)
	}

	pretty, err := MarshalIndent(node, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}
	for _, lexeme := range []string{"900719925474099312345", "1.2300", "1E+09", `"a\u0062"`} {
		if !strings.Contains(string(pretty), lexeme) {
			t.Fatalf("pretty output lost %q: %s", lexeme, pretty)
		}
	}
}

func TestParseRejectsDecodedDuplicateKeys(t *testing.T) {
	_, err := Parse([]byte(`{"tag":"one","\u0074ag":"two"}`), DefaultLimits())
	if err == nil {
		t.Fatal("Parse() accepted duplicate decoded keys")
	}
	var parseErr *ParseError
	if !errors.As(err, &parseErr) || parseErr.Code != "duplicate_json_key" {
		t.Fatalf("Parse() error = %v, want duplicate_json_key", err)
	}
}

func TestParseEnforcesLimits(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		limits Limits
	}{
		{name: "bytes", input: `{"a":1}`, limits: Limits{MaxBytes: 3}},
		{name: "depth", input: `[[[]]]`, limits: Limits{MaxDepth: 2}},
		{name: "values", input: `[1,2,3]`, limits: Limits{MaxValues: 3}},
		{name: "string", input: `"abcd"`, limits: Limits{MaxStringBytes: 3}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(test.input), test.limits)
			var parseErr *ParseError
			if !errors.As(err, &parseErr) || parseErr.Code != "json_limit_exceeded" {
				t.Fatalf("Parse() error = %v, want json_limit_exceeded", err)
			}
		})
	}
}

func TestLimitsCannotExceedGlobalHardCaps(t *testing.T) {
	limits := normalizeLimits(Limits{
		MaxBytes:       GlobalMaxBytes + 1,
		MaxDepth:       GlobalMaxDepth + 1,
		MaxValues:      GlobalMaxValues + 1,
		MaxStringBytes: GlobalMaxStringBytes + 1,
	})
	want := Limits{
		MaxBytes:       GlobalMaxBytes,
		MaxDepth:       GlobalMaxDepth,
		MaxValues:      GlobalMaxValues,
		MaxStringBytes: GlobalMaxStringBytes,
	}
	if limits != want {
		t.Fatalf("limits = %+v, want %+v", limits, want)
	}
}

func TestParseRejectsMalformedNumbers(t *testing.T) {
	for _, input := range []string{`01`, `1.`, `1e`, `--1`, `+1`} {
		t.Run(input, func(t *testing.T) {
			if _, err := Parse([]byte(input), DefaultLimits()); err == nil {
				t.Fatalf("Parse(%q) succeeded", input)
			}
		})
	}
}

func TestParseRejectsUnpairedUnicodeSurrogates(t *testing.T) {
	for _, input := range []string{`"\ud800"`, `"\udfff"`, `"\ud800\u0041"`} {
		if _, err := Parse([]byte(input), DefaultLimits()); err == nil {
			t.Fatalf("Parse(%s) accepted an unpaired surrogate", input)
		}
	}
	if _, err := Parse([]byte(`"\ud83d\ude00"`), DefaultLimits()); err != nil {
		t.Fatalf("Parse() rejected a valid surrogate pair: %v", err)
	}
}

func TestOpaqueV1SortsAndExcludesOnlyRootDisplayName(t *testing.T) {
	node, err := Parse([]byte(`{"z":1.00,"tag":"display","nested":{"tag":"identity","a":2},"a":3}`), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	projection, err := MarshalOpaqueV1(node, "tag")
	if err != nil {
		t.Fatalf("MarshalOpaqueV1() error = %v", err)
	}
	want := `{"a":3,"nested":{"a":2,"tag":"identity"},"z":1.00}`
	if string(projection) != want {
		t.Fatalf("projection\nwant: %s\n got: %s", want, projection)
	}
}

func TestCloneAndSetStringMemberAreIsolated(t *testing.T) {
	original, err := Parse([]byte(`{"type":"vless","tag":"old","x":1}`), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	clone := original.Clone()
	if _, _, err := clone.SetStringMember("tag", "new"); err != nil {
		t.Fatalf("SetStringMember() error = %v", err)
	}

	originalJSON, _ := MarshalCompact(original)
	cloneJSON, _ := MarshalCompact(clone)
	if string(originalJSON) != `{"type":"vless","tag":"old","x":1}` {
		t.Fatalf("original mutated: %s", originalJSON)
	}
	if string(cloneJSON) != `{"type":"vless","tag":"new","x":1}` {
		t.Fatalf("clone = %s", cloneJSON)
	}
}

func FuzzParseRoundTrip(f *testing.F) {
	for _, seed := range []string{
		`null`,
		`{"type":"future","tag":"node","number":900719925474099312345,"ratio":1.2300}`,
		`[true,false,{"escaped":"a\u0062","nested":[1E+09]}]`,
		`{"duplicate":1,"duplicate":2}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		limits := DefaultLimits()
		limits.MaxBytes = 1 << 20
		node, err := Parse([]byte(input), limits)
		if err != nil {
			return
		}
		encoded, err := MarshalCompact(node)
		if err != nil {
			t.Fatalf("MarshalCompact() error = %v", err)
		}
		reparsed, err := Parse(encoded, limits)
		if err != nil {
			t.Fatalf("round-trip Parse() error = %v; encoded = %q", err, encoded)
		}
		firstProjection, err := MarshalOpaqueV1(node, "tag")
		if err != nil {
			t.Fatalf("first projection error = %v", err)
		}
		secondProjection, err := MarshalOpaqueV1(reparsed, "tag")
		if err != nil {
			t.Fatalf("second projection error = %v", err)
		}
		if string(firstProjection) != string(secondProjection) {
			t.Fatalf("projection changed\nfirst:  %s\nsecond: %s", firstProjection, secondProjection)
		}
	})
}
