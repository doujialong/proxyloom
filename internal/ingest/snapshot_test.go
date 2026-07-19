package ingest

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/format/singbox"
	"github.com/doujialong/proxyloom/internal/identity"
	"github.com/doujialong/proxyloom/internal/occurrence"
	"github.com/doujialong/proxyloom/internal/protocol"
)

func TestProcessReusesOccurrenceAcrossTagAndOrderChanges(t *testing.T) {
	fingerprinter, _ := identity.NewFingerprinter(bytes.Repeat([]byte{0x31}, 32), "fixture-key")
	processor, err := NewProcessor(protocol.NewRegistry(), fingerprinter, singbox.DefaultLimits())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	next := 0
	newID := func() string { next++; return fmt.Sprintf("occ-%d", next) }
	firstInput := []byte(`[{"type":"vless","tag":"old","server":"198.51.100.1","server_port":443,"future":{"b":2,"a":1}}]`)
	first, err := processor.Process(firstInput, nil, Options{SourceID: "source-a", Now: now, NewOccurrenceID: newID})
	if err != nil {
		t.Fatalf("first Process() error = %v", err)
	}
	secondInput := []byte(`[{"future":{"a":1,"b":2},"server_port":443,"server":"198.51.100.1","tag":"new","type":"vless"}]`)
	second, err := processor.Process(secondInput, first.Occurrences, Options{SourceID: "source-a", Now: now.Add(time.Hour), NewOccurrenceID: newID})
	if err != nil {
		t.Fatalf("second Process() error = %v", err)
	}
	if second.Nodes[0].OccurrenceID != "occ-1" || second.Nodes[0].MatchMethod != occurrence.MatchFingerprintUnique {
		t.Fatalf("second node = %+v", second.Nodes[0])
	}
	if next != 1 {
		t.Fatalf("ID generator called %d times, want 1", next)
	}
}

func TestNewProcessorRequiresFingerprinter(t *testing.T) {
	if _, err := NewProcessor(nil, nil, singbox.DefaultLimits()); err == nil {
		t.Fatal("NewProcessor() accepted a nil fingerprinter")
	}
}
