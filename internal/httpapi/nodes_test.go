package httpapi

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestNodeCursorRoundTrip(t *testing.T) {
	want := nodeCursor{
		LastSeenAt: time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC).UnixMilli(),
		ID:         "11111111-1111-4111-8111-111111111111",
		SourceID:   "22222222-2222-4222-8222-222222222222",
		Protocol:   "vless",
		Health:     "healthy",
		ExpiresAt:  time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC).Unix(),
	}
	encoded, err := encodeNodeCursor(want)
	if err != nil {
		t.Fatalf("encode cursor: %v", err)
	}
	got, err := decodeNodeCursor(encoded)
	if err != nil {
		t.Fatalf("decode cursor: %v", err)
	}
	if got != want {
		t.Fatalf("cursor = %+v, want %+v", got, want)
	}
}

func TestNodeCursorRejectsTrailingJSON(t *testing.T) {
	encoded, err := encodeNodeCursor(nodeCursor{
		LastSeenAt: 1,
		ID:         "11111111-1111-4111-8111-111111111111",
		ExpiresAt:  2,
	})
	if err != nil {
		t.Fatalf("encode cursor: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	malformed := base64.RawURLEncoding.EncodeToString(append(raw, []byte(`{}`)...))
	if _, err := decodeNodeCursor(malformed); err == nil {
		t.Fatal("cursor with trailing JSON was accepted")
	}
}
