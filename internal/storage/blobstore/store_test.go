package blobstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/crypto/envelope"
	"github.com/doujialong/proxyloom/internal/crypto/keyring"
	"github.com/doujialong/proxyloom/internal/crypto/masterkey"
	storagesqlite "github.com/doujialong/proxyloom/internal/storage/sqlite"
	_ "modernc.org/sqlite"
)

func TestPutGetInlineBlob(t *testing.T) {
	store, database, ring := testStore(t, 1024)
	defer database.Close()
	defer ring.Close()
	plaintext := []byte("fixture inline secret")
	record, err := store.Put(context.Background(), PutRequest{Kind: "raw_node", Plaintext: plaintext})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if record.External {
		t.Fatal("small blob was stored externally")
	}
	var ciphertext []byte
	var relativePath sql.NullString
	if err := database.QueryRow("SELECT ciphertext_inline, relative_path FROM encrypted_blobs WHERE id = ?", record.ID).Scan(&ciphertext, &relativePath); err != nil {
		t.Fatal(err)
	}
	if relativePath.Valid || bytes.Contains(ciphertext, plaintext) {
		t.Fatalf("inline storage leaked plaintext or path: path=%+v ciphertext=%x", relativePath, ciphertext)
	}
	loaded, loadedRecord, err := store.Get(context.Background(), record.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !bytes.Equal(loaded, plaintext) || loadedRecord.ID != record.ID {
		t.Fatalf("loaded = %q, %+v", loaded, loadedRecord)
	}
}

func TestPutGetExternalBlob(t *testing.T) {
	store, database, ring := testStore(t, 8)
	defer database.Close()
	defer ring.Close()
	plaintext := bytes.Repeat([]byte("external-secret-"), 32)
	record, err := store.Put(context.Background(), PutRequest{Kind: "raw_document", Plaintext: plaintext, Public: true})
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if !record.External || len(record.PublicSHA256) != 64 {
		t.Fatalf("record = %+v", record)
	}
	var relativePath string
	if err := database.QueryRow("SELECT relative_path FROM encrypted_blobs WHERE id = ?", record.ID).Scan(&relativePath); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.root, filepath.FromSlash(relativePath))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("external blob mode = %o", info.Mode().Perm())
	}
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("external ciphertext contains plaintext")
	}
	loaded, _, err := store.Get(context.Background(), record.ID)
	if err != nil || !bytes.Equal(loaded, plaintext) {
		t.Fatalf("Get() = %q, %v", loaded, err)
	}
}

func TestGetRejectsInlineTamperingAndCiphertextSwap(t *testing.T) {
	store, database, ring := testStore(t, 1024)
	defer database.Close()
	defer ring.Close()
	first, err := store.Put(context.Background(), PutRequest{Kind: "raw_node", Plaintext: []byte("first-secret")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Put(context.Background(), PutRequest{Kind: "raw_node", Plaintext: []byte("other-secret")})
	if err != nil {
		t.Fatal(err)
	}
	var secondCiphertext []byte
	if err := database.QueryRow("SELECT ciphertext_inline FROM encrypted_blobs WHERE id = ?", second.ID).Scan(&secondCiphertext); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE encrypted_blobs SET ciphertext_inline = ?, ciphertext_size = ? WHERE id = ?", secondCiphertext, len(secondCiphertext), first.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(context.Background(), first.ID); !errors.Is(err, envelope.ErrIntegrity) {
		t.Fatalf("Get(swapped) error = %v", err)
	}
	if _, err := database.Exec("UPDATE encrypted_blobs SET content_hmac = zeroblob(32) WHERE id = ?", second.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(context.Background(), second.ID); !errors.Is(err, envelope.ErrIntegrity) {
		t.Fatalf("Get(HMAC tampered) error = %v", err)
	}
}

func TestGetRejectsPublicDigestTampering(t *testing.T) {
	store, database, ring := testStore(t, 1024)
	defer database.Close()
	defer ring.Close()
	record, err := store.Put(context.Background(), PutRequest{
		Kind: "artifact", Plaintext: []byte("public artifact"), Public: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(
		"UPDATE encrypted_blobs SET public_sha256 = ? WHERE id = ?",
		strings.Repeat("0", 64), record.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(context.Background(), record.ID); !errors.Is(err, envelope.ErrIntegrity) {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestGetRejectsExternalBitFlip(t *testing.T) {
	store, database, ring := testStore(t, 8)
	defer database.Close()
	defer ring.Close()
	record, err := store.Put(context.Background(), PutRequest{Kind: "artifact", Plaintext: bytes.Repeat([]byte("x"), 128)})
	if err != nil {
		t.Fatal(err)
	}
	var relativePath string
	if err := database.QueryRow("SELECT relative_path FROM encrypted_blobs WHERE id = ?", record.ID).Scan(&relativePath); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.root, filepath.FromSlash(relativePath))
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 0x80
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(context.Background(), record.ID); !errors.Is(err, envelope.ErrIntegrity) {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestGetRejectsExternalPathMismatch(t *testing.T) {
	store, database, ring := testStore(t, 8)
	defer database.Close()
	defer ring.Close()
	record, err := store.Put(context.Background(), PutRequest{Kind: "artifact", Plaintext: bytes.Repeat([]byte("x"), 128)})
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.ToSlash(filepath.Join("ff", record.ID+".blob"))
	if _, err := database.Exec("UPDATE encrypted_blobs SET relative_path = ? WHERE id = ?", wrongPath, record.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(context.Background(), record.ID); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestGetRejectsExternalSymlink(t *testing.T) {
	store, database, ring := testStore(t, 8)
	defer database.Close()
	defer ring.Close()
	record, err := store.Put(context.Background(), PutRequest{Kind: "artifact", Plaintext: bytes.Repeat([]byte("x"), 128)})
	if err != nil {
		t.Fatal(err)
	}
	var relativePath string
	if err := database.QueryRow("SELECT relative_path FROM encrypted_blobs WHERE id = ?", record.ID).Scan(&relativePath); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.root, filepath.FromSlash(relativePath))
	target := filepath.Join(t.TempDir(), "target.blob")
	if err := os.WriteFile(target, bytes.Repeat([]byte("z"), 144), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(context.Background(), record.ID); err == nil {
		t.Fatal("Get() followed an external blob symlink")
	}
}

func TestExternalBlobPublicationDoesNotOverwrite(t *testing.T) {
	store, database, ring := testStore(t, 8)
	defer database.Close()
	defer ring.Close()
	want := bytes.Repeat([]byte("first"), 32)
	record, err := store.Put(context.Background(), PutRequest{Kind: "artifact", Plaintext: want})
	if err != nil {
		t.Fatal(err)
	}
	colliding, err := New(database, ring, Options{
		Root:            store.root,
		InlineThreshold: 8,
		MaxPlaintext:    1 << 20,
		Random:          incrementingReader(1024),
		Now:             func() time.Time { return testTime },
		NewID:           func() string { return record.ID },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := colliding.Put(context.Background(), PutRequest{
		Kind: "artifact", Plaintext: bytes.Repeat([]byte("second"), 32),
	}); err == nil {
		t.Fatal("Put() overwrote an existing external blob")
	}
	got, _, err := store.Get(context.Background(), record.ID)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Get(original) = %q, %v", got, err)
	}
}

func TestExternalBlobIsRemovedWhenDatabaseInsertFails(t *testing.T) {
	store, database, ring := testStore(t, 8)
	defer database.Close()
	defer ring.Close()
	root := store.root
	if _, err := database.Exec(`
CREATE TRIGGER reject_blob_insert
BEFORE INSERT ON encrypted_blobs
BEGIN
  SELECT RAISE(ABORT, 'forced blob insert failure');
END`); err != nil {
		t.Fatal(err)
	}
	_, err := store.Put(context.Background(), PutRequest{Kind: "raw_document", Plaintext: bytes.Repeat([]byte("x"), 128)})
	if err == nil {
		t.Fatal("Put() succeeded when its database insert should fail")
	}
	var blobFiles []string
	filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr == nil && info.Mode().IsRegular() {
			blobFiles = append(blobFiles, path)
		}
		return walkErr
	})
	if len(blobFiles) != 0 {
		t.Fatalf("orphan blob files remain: %v", blobFiles)
	}
}

func TestNewRejectsInsecureRootAndPutLimits(t *testing.T) {
	database, ring := testDatabaseAndKeys(t)
	defer database.Close()
	defer ring.Close()
	root := filepath.Join(t.TempDir(), "blobs")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(database, ring, Options{
		Root: root, Random: bytes.NewReader(make([]byte, 128)),
		Now: func() time.Time { return testTime }, NewID: testIDGenerator(),
	}); err == nil {
		t.Fatal("New() accepted insecure blob root")
	}
	store, err := New(database, ring, Options{
		Root: filepath.Join(t.TempDir(), "private"), MaxPlaintext: 4, InlineThreshold: 4,
		Random: bytes.NewReader(make([]byte, 128)),
		Now:    func() time.Time { return testTime }, NewID: testIDGenerator(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), PutRequest{Kind: "raw_node", Plaintext: []byte("12345")}); err == nil {
		t.Fatal("Put() accepted oversized plaintext")
	}
}

var testTime = time.Date(2026, 7, 18, 9, 0, 0, 0, time.UTC)

func testStore(t *testing.T, inlineThreshold int) (*Store, *sql.DB, *keyring.Ring) {
	t.Helper()
	database, ring := testDatabaseAndKeys(t)
	store, err := New(database, ring, Options{
		Root:            filepath.Join(t.TempDir(), "blobs"),
		InlineThreshold: inlineThreshold,
		MaxPlaintext:    1 << 20,
		Random:          incrementingReader(1 << 20),
		Now:             func() time.Time { return testTime },
		NewID:           testIDGenerator(),
	})
	if err != nil {
		database.Close()
		ring.Close()
		t.Fatal(err)
	}
	return store, database, ring
}

func testDatabaseAndKeys(t *testing.T) (*sql.DB, *keyring.Ring) {
	t.Helper()
	database, err := sql.Open(storagesqlite.DriverName, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	if _, err := database.Exec("PRAGMA foreign_keys = ON"); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if err := storagesqlite.Migrate(context.Background(), database, storagesqlite.MigrateOptions{
		Now: func() time.Time { return testTime },
	}); err != nil {
		database.Close()
		t.Fatal(err)
	}
	master := masterkey.Key{ID: "00000000-0000-4000-8000-000000000001"}
	for index := range master.Material {
		master.Material[index] = 0x42
	}
	ring, err := storagesqlite.BootstrapKeys(context.Background(), database, master, storagesqlite.KeyBootstrapOptions{
		Now:    testTime,
		Random: incrementingReader(1 << 20),
		NewID:  bootstrapIDGenerator(),
	})
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	return database, ring
}

func bootstrapIDGenerator() func() string {
	next := 0
	return func() string {
		next++
		return fmt.Sprintf("00000000-0000-7000-8000-%012d", next)
	}
}

func testIDGenerator() func() string {
	next := 100
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
