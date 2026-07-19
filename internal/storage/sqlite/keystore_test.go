package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/crypto/envelope"
	"github.com/doujialong/proxyloom/internal/crypto/keyring"
	"github.com/doujialong/proxyloom/internal/crypto/masterkey"
)

func TestBootstrapAndLoadKeys(t *testing.T) {
	database := openMigratedTestDatabaseAt(t, filepath.Join(t.TempDir(), "proxyloom.db"))
	defer database.Close()
	master := fixtureMasterKey(0x44)
	nextID := fixtureIDGenerator()
	ring, err := BootstrapKeys(context.Background(), database, master, KeyBootstrapOptions{
		Now:    migrationTime,
		Random: incrementingReader(1024),
		NewID:  nextID,
	})
	if err != nil {
		t.Fatalf("BootstrapKeys() error = %v", err)
	}
	defer ring.Close()
	if ring.InstanceID() != "00000000-0000-7000-8000-000000000001" {
		t.Fatalf("instance ID = %q", ring.InstanceID())
	}
	for _, purpose := range keyring.RequiredPurposes() {
		if _, err := ring.Active(purpose); err != nil {
			t.Fatalf("Active(%s) error = %v", purpose, err)
		}
	}

	loaded, err := LoadKeys(context.Background(), database, master)
	if err != nil {
		t.Fatalf("LoadKeys() error = %v", err)
	}
	defer loaded.Close()
	for _, purpose := range keyring.RequiredPurposes() {
		want, _ := ring.Active(purpose)
		got, _ := loaded.Active(purpose)
		if got != want {
			t.Fatalf("loaded %s key differs", purpose)
		}
	}
	var slots, keys, wrappings int
	if err := database.QueryRow("SELECT count(*) FROM master_key_slots").Scan(&slots); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT count(*) FROM data_keys").Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow("SELECT count(*) FROM master_key_wrappings").Scan(&wrappings); err != nil {
		t.Fatal(err)
	}
	if slots != 1 || keys != 6 || wrappings != 6 {
		t.Fatalf("crypto rows = slots %d, keys %d, wrappings %d", slots, keys, wrappings)
	}
}

func TestLoadKeysRejectsWrongMasterKey(t *testing.T) {
	database, master := bootstrappedKeyDatabase(t)
	defer database.Close()
	wrongID := fixtureMasterKey(0x44)
	wrongID.ID = "00000000-0000-4000-8000-000000000099"
	if _, err := LoadKeys(context.Background(), database, wrongID); !errors.Is(err, ErrMasterKeyMismatch) {
		t.Fatalf("LoadKeys(wrong ID) error = %v", err)
	}
	wrongMaterial := master
	wrongMaterial.Material[0] ^= 0xff
	if _, err := LoadKeys(context.Background(), database, wrongMaterial); !errors.Is(err, envelope.ErrIntegrity) {
		t.Fatalf("LoadKeys(wrong material) error = %v", err)
	}
}

func TestLoadKeysRejectsCanaryAndWrappingTampering(t *testing.T) {
	t.Run("canary", func(t *testing.T) {
		database, master := bootstrappedKeyDatabase(t)
		defer database.Close()
		if _, err := database.Exec(`
UPDATE master_key_slots
SET canary_ciphertext = substr(canary_ciphertext, 1, length(canary_ciphertext) - 1) || X'00'`); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeys(context.Background(), database, master); !errors.Is(err, envelope.ErrIntegrity) {
			t.Fatalf("LoadKeys() error = %v", err)
		}
	})
	t.Run("wrapping swap", func(t *testing.T) {
		database, master := bootstrappedKeyDatabase(t)
		defer database.Close()
		rows, err := database.Query("SELECT data_key_id, wrapped_key FROM master_key_wrappings ORDER BY data_key_id LIMIT 2")
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		var ciphertexts [][]byte
		for rows.Next() {
			var id string
			var ciphertext []byte
			if err := rows.Scan(&id, &ciphertext); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
			ciphertexts = append(ciphertexts, ciphertext)
		}
		rows.Close()
		if _, err := database.Exec("UPDATE master_key_wrappings SET wrapped_key = ? WHERE data_key_id = ?", ciphertexts[1], ids[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeys(context.Background(), database, master); !errors.Is(err, envelope.ErrIntegrity) {
			t.Fatalf("LoadKeys() error = %v", err)
		}
	})
	t.Run("missing active wrapping", func(t *testing.T) {
		database, master := bootstrappedKeyDatabase(t)
		defer database.Close()
		if _, err := database.Exec(`
DELETE FROM master_key_wrappings
WHERE data_key_id = (SELECT id FROM data_keys WHERE purpose = 'content_hmac')`); err != nil {
			t.Fatal(err)
		}
		_, err := LoadKeys(context.Background(), database, master)
		if !errors.Is(err, envelope.ErrIntegrity) {
			t.Fatalf("LoadKeys() error = %v", err)
		}
	})
	t.Run("missing decrypt-only wrapping", func(t *testing.T) {
		database, master := bootstrappedKeyDatabase(t)
		defer database.Close()
		if _, err := database.Exec(`
INSERT INTO data_keys(id, purpose, status, created_at)
VALUES ('00000000-0000-7000-8000-000000000099', 'blob', 'decrypt_only', ?)`, migrationTime.UnixMilli()); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeys(context.Background(), database, master); !errors.Is(err, envelope.ErrIntegrity) {
			t.Fatalf("LoadKeys() error = %v", err)
		}
	})
}

func TestBootstrapKeysIsAtomicAndSingleUse(t *testing.T) {
	database := openMigratedTestDatabaseAt(t, filepath.Join(t.TempDir(), "proxyloom.db"))
	defer database.Close()
	master := fixtureMasterKey(0x44)
	_, err := BootstrapKeys(context.Background(), database, master, KeyBootstrapOptions{
		Now:    migrationTime,
		Random: bytes.NewReader(make([]byte, envelope.NonceBytes+8)),
		NewID:  fixtureIDGenerator(),
	})
	if err == nil {
		t.Fatal("BootstrapKeys() succeeded with insufficient random data")
	}
	for _, table := range []string{"instances", "master_key_slots", "data_keys", "master_key_wrappings"} {
		var count int
		if err := database.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("table %s count = %d, %v", table, count, err)
		}
	}
	ring, err := BootstrapKeys(context.Background(), database, master, KeyBootstrapOptions{
		Now:    migrationTime,
		Random: incrementingReader(1024),
		NewID:  fixtureIDGenerator(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ring.Close()
	if _, err := BootstrapKeys(context.Background(), database, master, KeyBootstrapOptions{
		Now:    migrationTime.Add(time.Second),
		Random: incrementingReader(1024),
		NewID:  fixtureIDGenerator(),
	}); !errors.Is(err, ErrCryptoAlreadyInitialized) {
		t.Fatalf("second BootstrapKeys() error = %v", err)
	}
}

func TestPrepareAndRecoverMasterKeyRotation(t *testing.T) {
	database, current := bootstrappedKeyDatabase(t)
	defer database.Close()
	next := fixtureMasterKey(0x77)
	next.ID = "00000000-0000-4000-8000-000000000002"
	if err := PrepareMasterKeyRotation(context.Background(), database, current, next, MasterKeyRotationOptions{
		Now: migrationTime.Add(time.Hour), Random: incrementingReader(1024),
	}); err != nil {
		t.Fatal(err)
	}
	if err := PrepareMasterKeyRotation(context.Background(), database, current, masterkey.Key{
		ID: "00000000-0000-4000-8000-000000000003", Material: next.Material,
	}, MasterKeyRotationOptions{
		Now: migrationTime.Add(2 * time.Hour), Random: incrementingReader(1024),
	}); !errors.Is(err, ErrMasterKeyRotationPending) {
		t.Fatalf("second prepared rotation error = %v", err)
	}
	currentRing, err := LoadKeys(context.Background(), database, current)
	if err != nil {
		t.Fatalf("current key stopped before file switch: %v", err)
	}
	defer currentRing.Close()
	nextRing, err := LoadKeys(context.Background(), database, next)
	if err != nil {
		t.Fatalf("prepared key recovery activation error = %v", err)
	}
	defer nextRing.Close()
	for _, purpose := range keyring.RequiredPurposes() {
		before, _ := currentRing.Active(purpose)
		after, _ := nextRing.Active(purpose)
		if before != after {
			t.Fatalf("data key %s changed during master key rotation", purpose)
		}
	}
	if _, err := LoadKeys(context.Background(), database, current); !errors.Is(err, ErrMasterKeyMismatch) {
		t.Fatalf("retired master key load error = %v", err)
	}
	var active, retired, wrappings int
	if err := database.QueryRow(`SELECT count(*) FROM master_key_slots WHERE state = 'active'`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT count(*) FROM master_key_slots WHERE state = 'retired'`).Scan(&retired); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT count(*) FROM master_key_wrappings`).Scan(&wrappings); err != nil {
		t.Fatal(err)
	}
	if active != 1 || retired != 1 || wrappings != 12 {
		t.Fatalf("rotation rows active=%d retired=%d wrappings=%d", active, retired, wrappings)
	}
}

func TestPreparedMasterKeyTamperingDoesNotActivate(t *testing.T) {
	database, current := bootstrappedKeyDatabase(t)
	defer database.Close()
	next := fixtureMasterKey(0x77)
	next.ID = "00000000-0000-4000-8000-000000000002"
	if err := PrepareMasterKeyRotation(context.Background(), database, current, next, MasterKeyRotationOptions{
		Now: migrationTime.Add(time.Hour), Random: incrementingReader(1024),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
UPDATE master_key_wrappings SET wrapped_key = zeroblob(length(wrapped_key))
WHERE master_key_id = ? AND data_key_id = (
  SELECT data_key_id FROM master_key_wrappings WHERE master_key_id = ? LIMIT 1
)`, next.ID, next.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeys(context.Background(), database, next); !errors.Is(err, envelope.ErrIntegrity) {
		t.Fatalf("tampered prepared key load error = %v", err)
	}
	currentRing, err := LoadKeys(context.Background(), database, current)
	if err != nil {
		t.Fatalf("current key was lost after failed activation: %v", err)
	}
	currentRing.Close()
}

func bootstrappedKeyDatabase(t *testing.T) (*sql.DB, masterkey.Key) {
	t.Helper()
	database := openMigratedTestDatabaseAt(t, filepath.Join(t.TempDir(), "proxyloom.db"))
	master := fixtureMasterKey(0x44)
	ring, err := BootstrapKeys(context.Background(), database, master, KeyBootstrapOptions{
		Now:    migrationTime,
		Random: incrementingReader(1024),
		NewID:  fixtureIDGenerator(),
	})
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	ring.Close()
	return database, master
}

func fixtureMasterKey(value byte) masterkey.Key {
	key := masterkey.Key{ID: "00000000-0000-4000-8000-000000000001"}
	for index := range key.Material {
		key.Material[index] = value
	}
	return key
}

func fixtureIDGenerator() func() string {
	next := 0
	return func() string {
		next++
		return fmt.Sprintf("00000000-0000-7000-8000-%012d", next)
	}
}

func incrementingReader(size int) *bytes.Reader {
	content := make([]byte, size)
	for index := range content {
		content[index] = byte(index)
	}
	return bytes.NewReader(content)
}
