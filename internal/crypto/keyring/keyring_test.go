package keyring

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRingProvidesEveryRequiredActiveKey(t *testing.T) {
	keys := fixtureKeys()
	decryptOnly := keys[0]
	decryptOnly.ID = "key-decrypt-only"
	decryptOnly.Status = StatusDecryptOnly
	keys = append(keys, decryptOnly)
	ring, err := New("instance-1", keys)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer ring.Close()
	if ring.InstanceID() != "instance-1" {
		t.Fatalf("InstanceID() = %q", ring.InstanceID())
	}
	for index, purpose := range RequiredPurposes() {
		active, err := ring.Active(purpose)
		if err != nil {
			t.Fatalf("Active(%s) error = %v", purpose, err)
		}
		if active != keys[index] {
			t.Fatalf("Active(%s) = %+v, want %+v", purpose, active, keys[index])
		}
		byID, err := ring.ByID(active.ID)
		if err != nil || byID != active {
			t.Fatalf("ByID(%q) = %+v, %v", active.ID, byID, err)
		}
	}
	if historical, err := ring.ByID(decryptOnly.ID); err != nil || historical != decryptOnly {
		t.Fatalf("ByID(decrypt-only) = %+v, %v", historical, err)
	}
}

func TestRingRejectsMissingAndDuplicateActivePurposes(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		keys := fixtureKeys()
		_, err := New("instance-1", keys[:len(keys)-1])
		if err == nil || !strings.Contains(err.Error(), `missing active key for purpose "content_hmac"`) {
			t.Fatalf("New() error = %v", err)
		}
	})
	t.Run("missing order is deterministic", func(t *testing.T) {
		_, err := New("instance-1", nil)
		if err == nil || !strings.Contains(err.Error(), `missing active key for purpose "data"`) {
			t.Fatalf("New() error = %v", err)
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		keys := fixtureKeys()
		duplicate := keys[0]
		duplicate.ID = "key-duplicate"
		keys = append(keys, duplicate)
		_, err := New("instance-1", keys)
		if err == nil || !strings.Contains(err.Error(), `multiple active keys for purpose "data"`) {
			t.Fatalf("New() error = %v", err)
		}
	})
}

func TestRingLookupAndClose(t *testing.T) {
	ring, err := New("instance-1", fixtureKeys())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.ByID("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("ByID(missing) error = %v", err)
	}
	if _, err := ring.Active(Purpose("unknown")); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Active(unknown) error = %v", err)
	}
	ring.Close()
	if ring.InstanceID() != "" {
		t.Fatalf("InstanceID() after Close = %q", ring.InstanceID())
	}
	if _, err := ring.ByID("key-1"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("ByID() after Close error = %v", err)
	}
	if _, err := ring.Active(PurposeData); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Active() after Close error = %v", err)
	}
	ring.Close()
}

func fixtureKeys() []DataKey {
	keys := make([]DataKey, 0, len(RequiredPurposes()))
	for index, purpose := range RequiredPurposes() {
		key := DataKey{
			ID:      fmt.Sprintf("key-%d", index+1),
			Purpose: purpose,
			Status:  StatusActive,
		}
		for materialIndex := range key.Material {
			key.Material[materialIndex] = byte(index + 1)
		}
		keys = append(keys, key)
	}
	return keys
}
