package managedbackup

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/crypto/masterkey"
	"github.com/doujialong/proxyloom/internal/storage/blobstore"
	storagesqlite "github.com/doujialong/proxyloom/internal/storage/sqlite"
	"github.com/google/uuid"
)

func TestEncryptedStreamRejectsWrongPassphraseCorruptionAndTruncation(t *testing.T) {
	passphrase := []byte("correct backup passphrase")
	plaintext := bytes.Repeat([]byte("proxyloom-stream-fixture\n"), 100000)
	var encrypted bytes.Buffer
	writer, err := newEncryptedWriter(&encrypted, passphrase, bytes.NewReader(bytes.Repeat([]byte{0x42}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := newEncryptedReader(bytes.NewReader(encrypted.Bytes()), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(bytes.Buffer)
	if _, err := decoded.ReadFrom(reader); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Bytes(), plaintext) {
		t.Fatal("encrypted stream round trip changed plaintext")
	}
	for name, content := range map[string][]byte{
		"corrupt": func() []byte {
			copy := append([]byte(nil), encrypted.Bytes()...)
			copy[len(copy)/2] ^= 0x80
			return copy
		}(),
		"truncated": append([]byte(nil), encrypted.Bytes()[:encrypted.Len()-1]...),
	} {
		t.Run(name, func(t *testing.T) {
			reader, err := newEncryptedReader(bytes.NewReader(content), passphrase)
			if err == nil {
				_, err = new(bytes.Buffer).ReadFrom(reader)
			}
			if err == nil {
				t.Fatal("damaged encrypted stream was accepted")
			}
		})
	}
	wrong, err := newEncryptedReader(bytes.NewReader(encrypted.Bytes()), []byte("wrong backup passphrase"))
	if err == nil {
		_, err = new(bytes.Buffer).ReadFrom(wrong)
	}
	if err == nil {
		t.Fatal("wrong backup passphrase was accepted")
	}
}

func TestManagedBackupCreateExtractAndVerify(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	masterPath := filepath.Join(root, "master.key")
	master, err := masterkey.Generate(masterPath, masterkey.GenerateOptions{Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	store, err := storagesqlite.Open(ctx, filepath.Join(dataDir, "proxyloom.db"), storagesqlite.OpenOptions{
		Migrate: storagesqlite.MigrateOptions{Now: time.Now},
	})
	if err != nil {
		t.Fatal(err)
	}
	ring, err := storagesqlite.BootstrapKeys(ctx, store.DB(), master, storagesqlite.KeyBootstrapOptions{
		Now: time.Now().UTC(), Random: rand.Reader, NewID: func() string { return uuid.New().String() },
	})
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := blobstore.New(store.DB(), ring, blobstore.Options{
		Root: filepath.Join(dataDir, "blobs"), InlineThreshold: 16,
		Random: rand.Reader, Now: time.Now, NewID: func() string { return uuid.New().String() },
	})
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte("managed-backup-secret"), 100)
	if _, err := blobs.Put(ctx, blobstore.PutRequest{Kind: "fixture", Plaintext: secret}); err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("portable backup passphrase")
	backupPath := filepath.Join(root, "proxyloom.plbk")
	info, err := Create(ctx, store.DB(), dataDir, master, passphrase, backupPath, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if info.Size == 0 || info.SHA256 == "" || info.FileCount < 3 {
		t.Fatalf("backup info = %+v", info)
	}
	ring.Close()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	extracted, err := ExtractAndVerify(ctx, backupPath, filepath.Join(root, "restore"), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(extracted.Root)
	defer wipe(extracted.Master.Material[:])
	if extracted.Master.ID != master.ID || extracted.Manifest.SchemaVersion != info.SchemaVersion {
		t.Fatalf("extracted backup = %+v", extracted.Manifest)
	}
	wrongRoot := filepath.Join(root, "wrong")
	if _, err := ExtractAndVerify(ctx, backupPath, wrongRoot, []byte("incorrect passphrase")); err == nil {
		t.Fatal("backup accepted an incorrect passphrase")
	}
	if _, err := os.Lstat(wrongRoot); !os.IsNotExist(err) {
		t.Fatalf("failed restore left staging data: %v", err)
	}
}
