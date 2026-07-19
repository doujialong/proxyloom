package ingest

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/format/urilist"
	"github.com/doujialong/proxyloom/internal/identity"
	"github.com/doujialong/proxyloom/internal/occurrence"
	"github.com/doujialong/proxyloom/internal/protocol"
)

func TestURIProcessorReusesOccurrenceAcrossDisplayFragmentAndContainerChanges(t *testing.T) {
	fingerprinter, _ := identity.NewFingerprinter(bytes.Repeat([]byte{0x61}, 32), "fixture-key")
	processor, err := NewURIProcessor(protocol.NewRegistry(), fingerprinter, urilist.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 18, 13, 0, 0, 0, time.UTC)
	next := 0
	newID := func() string { next++; return fmt.Sprintf("occ-%d", next) }
	first, err := processor.Process(
		[]byte("vless://fixture@example.test:443?security=tls#Old%20Name"), nil,
		Options{SourceID: "source-uri", Now: now, NewOccurrenceID: newID},
	)
	if err != nil {
		t.Fatal(err)
	}
	renamedPlain := []byte("vless://fixture@example.test:443?security=tls#New%20Name\n")
	encoded := base64.StdEncoding.EncodeToString(renamedPlain)
	second, err := processor.Process(
		[]byte(encoded), first.Occurrences,
		Options{SourceID: "source-uri", Now: now.Add(time.Hour), NewOccurrenceID: newID},
	)
	if err != nil {
		t.Fatal(err)
	}
	if second.Document.Encoding != urilist.EncodingBase64Standard ||
		second.Nodes[0].OccurrenceID != first.Nodes[0].OccurrenceID ||
		second.Nodes[0].MatchMethod != occurrence.MatchFingerprintUnique || next != 1 {
		t.Fatalf("second URI snapshot = %+v, next=%d", second.Nodes[0], next)
	}
	if first.Nodes[0].Fingerprint.Digest != second.Nodes[0].Fingerprint.Digest || second.Nodes[0].Raw.DisplayName != "New Name" {
		t.Fatalf("fragment rename changed identity: first=%+v second=%+v", first.Nodes[0], second.Nodes[0])
	}
}

func TestURIProcessorKeepsUnknownFragmentInOpaqueFingerprint(t *testing.T) {
	fingerprinter, _ := identity.NewFingerprinter(bytes.Repeat([]byte{0x62}, 32), "fixture-key")
	processor, _ := NewURIProcessor(nil, fingerprinter, urilist.DefaultLimits())
	now := time.Date(2026, 7, 18, 13, 0, 0, 0, time.UTC)
	first, err := processor.Process([]byte("future://payload#one"), nil, Options{
		SourceID: "source-uri", Now: now, NewOccurrenceID: func() string { return "occ-1" },
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := processor.Process([]byte("future://payload#two"), first.Occurrences, Options{
		SourceID: "source-uri", Now: now.Add(time.Hour), NewOccurrenceID: func() string { return "occ-2" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Nodes[0].Raw.ProtocolID != protocol.UnknownID || first.Nodes[0].Raw.DisplayName != "" {
		t.Fatalf("unknown node = %+v", first.Nodes[0].Raw)
	}
	if first.Nodes[0].Fingerprint.Digest == second.Nodes[0].Fingerprint.Digest {
		t.Fatal("unknown URI fragment was incorrectly excluded from opaque identity")
	}
}
