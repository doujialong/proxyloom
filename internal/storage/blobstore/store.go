package blobstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/doujialong/proxyloom/internal/crypto/envelope"
	"github.com/doujialong/proxyloom/internal/crypto/keyring"
)

const (
	DefaultInlineThreshold = 64 << 10
	DefaultMaxPlaintext    = 50 << 20
)

var (
	ErrNotFound      = errors.New("encrypted blob not found")
	ErrInvalidRecord = errors.New("invalid encrypted blob record")
)

type Options struct {
	Root            string
	InlineThreshold int
	MaxPlaintext    int
	Random          io.Reader
	Now             func() time.Time
	NewID           func() string
}

type Store struct {
	database        *sql.DB
	keys            *keyring.Ring
	root            string
	inlineThreshold int
	maxPlaintext    int
	random          io.Reader
	now             func() time.Time
	newID           func() string
}

type PutRequest struct {
	Kind      string
	Plaintext []byte
	Public    bool
}

type Record struct {
	ID            string
	Kind          string
	KeyID         string
	PlaintextSize int
	External      bool
	PublicSHA256  string
	CreatedAt     time.Time
}

type GarbageStats struct {
	Marked       int64
	Unmarked     int64
	Deleted      int
	DeletedBytes int64
}

const durableReferencePredicate = `
  EXISTS (SELECT 1 FROM source_revisions WHERE config_blob_id = encrypted_blobs.id)
  OR EXISTS (SELECT 1 FROM raw_documents WHERE blob_id = encrypted_blobs.id)
  OR EXISTS (SELECT 1 FROM raw_nodes WHERE raw_blob_id = encrypted_blobs.id OR original_name_blob_id = encrypted_blobs.id)
  OR EXISTS (SELECT 1 FROM canonical_nodes WHERE canonical_blob_id = encrypted_blobs.id)
  OR EXISTS (SELECT 1 FROM artifacts WHERE content_blob_id = encrypted_blobs.id)
  OR EXISTS (SELECT 1 FROM managed_resources WHERE config_blob_id = encrypted_blobs.id)
  OR EXISTS (SELECT 1 FROM managed_outputs WHERE allocation_blob_id = encrypted_blobs.id)
  OR EXISTS (SELECT 1 FROM managed_output_artifacts WHERE content_blob_id = encrypted_blobs.id OR manifest_blob_id = encrypted_blobs.id)`

func New(database *sql.DB, keys *keyring.Ring, options Options) (*Store, error) {
	if database == nil {
		return nil, fmt.Errorf("database is required")
	}
	if keys == nil || keys.InstanceID() == "" {
		return nil, fmt.Errorf("keyring is required")
	}
	if options.Root == "" {
		return nil, fmt.Errorf("blob root is required")
	}
	if options.Random == nil || options.Now == nil || options.NewID == nil {
		return nil, fmt.Errorf("blob random source, clock and ID generator are required")
	}
	if options.InlineThreshold <= 0 {
		options.InlineThreshold = DefaultInlineThreshold
	}
	if options.MaxPlaintext <= 0 {
		options.MaxPlaintext = DefaultMaxPlaintext
	}
	if options.InlineThreshold > options.MaxPlaintext {
		return nil, fmt.Errorf("inline threshold exceeds maximum plaintext size")
	}
	root, err := prepareRoot(options.Root)
	if err != nil {
		return nil, err
	}
	return &Store{
		database:        database,
		keys:            keys,
		root:            root,
		inlineThreshold: options.InlineThreshold,
		maxPlaintext:    options.MaxPlaintext,
		random:          options.Random,
		now:             options.Now,
		newID:           options.NewID,
	}, nil
}

func (s *Store) Put(ctx context.Context, request PutRequest) (Record, error) {
	if s == nil || s.database == nil || s.keys == nil {
		return Record{}, fmt.Errorf("blob store is not initialized")
	}
	if !validKind(request.Kind) {
		return Record{}, fmt.Errorf("invalid blob kind %q", request.Kind)
	}
	if len(request.Plaintext) > s.maxPlaintext {
		return Record{}, fmt.Errorf("blob plaintext exceeds %d bytes", s.maxPlaintext)
	}
	id := s.newID()
	if !validID(id) {
		return Record{}, fmt.Errorf("blob ID generator returned an invalid ID")
	}
	createdAt := s.now().UTC()
	if createdAt.IsZero() {
		return Record{}, fmt.Errorf("blob clock returned zero time")
	}
	blobKey, err := s.keys.Active(keyring.PurposeBlob)
	if err != nil {
		return Record{}, err
	}
	sealed, err := envelope.Seal(blobKey.Material, request.Plaintext, blobContext(s.keys.InstanceID(), request.Kind, id), s.random)
	if err != nil {
		return Record{}, fmt.Errorf("seal blob %s: %w", id, err)
	}
	contentKey, err := s.keys.Active(keyring.PurposeContent)
	if err != nil {
		return Record{}, err
	}
	contentHMAC := sumContentHMAC(contentKey.Material, request.Kind, request.Plaintext)
	publicSHA256 := ""
	if request.Public {
		digest := sha256.Sum256(request.Plaintext)
		publicSHA256 = hex.EncodeToString(digest[:])
	}

	record := Record{
		ID:            id,
		Kind:          request.Kind,
		KeyID:         blobKey.ID,
		PlaintextSize: len(request.Plaintext),
		External:      len(request.Plaintext) > s.inlineThreshold,
		PublicSHA256:  publicSHA256,
		CreatedAt:     createdAt,
	}
	var relativePath string
	var ciphertextInline []byte
	var externalPath string
	if record.External {
		relativePath, externalPath, err = s.writeExternalCiphertext(id, sealed.Ciphertext)
		if err != nil {
			return Record{}, err
		}
	} else {
		ciphertextInline = sealed.Ciphertext
	}
	removeExternal := record.External
	defer func() {
		if removeExternal {
			_ = os.Remove(externalPath)
			_ = syncDirectory(filepath.Dir(externalPath))
		}
	}()

	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, fmt.Errorf("begin blob insert: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	var publicDigest interface{}
	if publicSHA256 != "" {
		publicDigest = publicSHA256
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO encrypted_blobs(
  id, kind, key_id, format_version, aad_version, nonce,
  ciphertext_inline, relative_path, plaintext_size, ciphertext_size,
  content_hmac, public_sha256, created_at
) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, request.Kind, blobKey.ID, sealed.FormatVersion, sealed.Nonce,
		ciphertextInline, nullableString(relativePath), len(request.Plaintext), len(sealed.Ciphertext),
		contentHMAC, publicDigest, createdAt.UnixMilli(),
	); err != nil {
		return Record{}, fmt.Errorf("insert encrypted blob %s: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return Record{}, fmt.Errorf("commit encrypted blob %s: %w", id, err)
	}
	rollback = false
	removeExternal = false
	return record, nil
}

func (s *Store) Get(ctx context.Context, id string) ([]byte, Record, error) {
	if s == nil || s.database == nil || s.keys == nil {
		return nil, Record{}, fmt.Errorf("blob store is not initialized")
	}
	if !validID(id) {
		return nil, Record{}, ErrNotFound
	}
	var record Record
	var formatVersion uint32
	var aadVersion uint32
	var nonce []byte
	var ciphertextInline []byte
	var relativePath sql.NullString
	var ciphertextSize int
	var contentHMAC []byte
	var publicSHA256 sql.NullString
	var createdAt int64
	err := s.database.QueryRowContext(ctx, `
SELECT id, kind, key_id, format_version, aad_version, nonce,
       ciphertext_inline, relative_path, plaintext_size, ciphertext_size,
       content_hmac, public_sha256, created_at
FROM encrypted_blobs WHERE id = ?`, id).Scan(
		&record.ID, &record.Kind, &record.KeyID, &formatVersion, &aadVersion, &nonce,
		&ciphertextInline, &relativePath, &record.PlaintextSize, &ciphertextSize,
		&contentHMAC, &publicSHA256, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, Record{}, ErrNotFound
	}
	if err != nil {
		return nil, Record{}, fmt.Errorf("read encrypted blob %s: %w", id, err)
	}
	if !validKind(record.Kind) || record.PlaintextSize < 0 || record.PlaintextSize > s.maxPlaintext ||
		ciphertextSize != record.PlaintextSize+16 || aadVersion != 1 {
		return nil, Record{}, ErrInvalidRecord
	}
	record.External = relativePath.Valid
	record.CreatedAt = time.UnixMilli(createdAt).UTC()
	if publicSHA256.Valid {
		record.PublicSHA256 = publicSHA256.String
		if len(record.PublicSHA256) != 64 {
			return nil, Record{}, ErrInvalidRecord
		}
	}
	var ciphertext []byte
	if record.External {
		if len(ciphertextInline) != 0 || !safeRelativePath(relativePath.String) ||
			relativePath.String != blobRelativePath(record.ID) {
			return nil, Record{}, ErrInvalidRecord
		}
		ciphertext, err = s.readExternalCiphertext(relativePath.String, ciphertextSize)
		if err != nil {
			return nil, Record{}, err
		}
	} else {
		if relativePath.Valid || len(ciphertextInline) != ciphertextSize {
			return nil, Record{}, ErrInvalidRecord
		}
		ciphertext = ciphertextInline
	}
	blobKey, err := s.keys.ByID(record.KeyID)
	if err != nil {
		return nil, Record{}, err
	}
	if blobKey.Purpose != keyring.PurposeBlob {
		return nil, Record{}, ErrInvalidRecord
	}
	plaintext, err := envelope.Open(blobKey.Material, envelope.Envelope{
		FormatVersion: formatVersion,
		Nonce:         nonce,
		Ciphertext:    ciphertext,
	}, blobContext(s.keys.InstanceID(), record.Kind, record.ID))
	if err != nil {
		return nil, Record{}, fmt.Errorf("open encrypted blob %s: %w", id, err)
	}
	if len(plaintext) != record.PlaintextSize {
		wipeBytes(plaintext)
		return nil, Record{}, envelope.ErrIntegrity
	}
	contentKey, err := s.keys.Active(keyring.PurposeContent)
	if err != nil {
		wipeBytes(plaintext)
		return nil, Record{}, err
	}
	wantHMAC := sumContentHMAC(contentKey.Material, record.Kind, plaintext)
	if subtle.ConstantTimeCompare(contentHMAC, wantHMAC) != 1 {
		wipeBytes(plaintext)
		return nil, Record{}, envelope.ErrIntegrity
	}
	if record.PublicSHA256 != "" {
		digest := sha256.Sum256(plaintext)
		if subtle.ConstantTimeCompare([]byte(record.PublicSHA256), []byte(hex.EncodeToString(digest[:]))) != 1 {
			wipeBytes(plaintext)
			return nil, Record{}, envelope.ErrIntegrity
		}
	}
	return plaintext, record, nil
}

// ContentMatches compares plaintext with a stored blob without decrypting or
// loading an external ciphertext file.
func (s *Store) ContentMatches(ctx context.Context, id, kind string, plaintext []byte) (bool, error) {
	if s == nil || s.database == nil || s.keys == nil || !validID(id) || !validKind(kind) {
		return false, ErrNotFound
	}
	contentKey, err := s.keys.Active(keyring.PurposeContent)
	if err != nil {
		return false, err
	}
	want := sumContentHMAC(contentKey.Material, kind, plaintext)
	var storedKind string
	var stored []byte
	if err := s.database.QueryRowContext(ctx, `
SELECT kind, content_hmac FROM encrypted_blobs WHERE id = ?`, id).Scan(&storedKind, &stored); errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	} else if err != nil {
		return false, fmt.Errorf("read blob content digest: %w", err)
	}
	return storedKind == kind && len(stored) == sha256.Size && subtle.ConstantTimeCompare(stored, want) == 1, nil
}

// DeleteUnreferenced removes a Blob only when no durable record points at it.
// Foreign-key ownership stays authoritative; callers cannot delete live data.
func (s *Store) DeleteUnreferenced(ctx context.Context, id string) (bool, error) {
	if s == nil || s.database == nil || !validID(id) {
		return false, ErrNotFound
	}
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin unreferenced blob deletion: %w", err)
	}
	defer tx.Rollback()
	var relativePath sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT relative_path FROM encrypted_blobs WHERE id = ?`, id).Scan(&relativePath); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("read unreferenced blob: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
DELETE FROM encrypted_blobs
WHERE id = ?
  AND NOT EXISTS (SELECT 1 FROM source_revisions WHERE config_blob_id = ?)
  AND NOT EXISTS (SELECT 1 FROM raw_documents WHERE blob_id = ?)
  AND NOT EXISTS (SELECT 1 FROM raw_nodes WHERE raw_blob_id = ? OR original_name_blob_id = ?)
  AND NOT EXISTS (SELECT 1 FROM canonical_nodes WHERE canonical_blob_id = ?)
  AND NOT EXISTS (SELECT 1 FROM artifacts WHERE content_blob_id = ?)
  AND NOT EXISTS (SELECT 1 FROM managed_resources WHERE config_blob_id = ?)
  AND NOT EXISTS (SELECT 1 FROM managed_outputs WHERE allocation_blob_id = ?)
  AND NOT EXISTS (SELECT 1 FROM managed_output_artifacts WHERE content_blob_id = ? OR manifest_blob_id = ?)`,
		id, id, id, id, id, id, id, id, id, id, id, id)
	if err != nil {
		return false, fmt.Errorf("delete unreferenced blob: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("confirm unreferenced blob deletion: %w", err)
	}
	if affected != 1 {
		return false, nil
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit unreferenced blob deletion: %w", err)
	}
	if relativePath.Valid {
		path := filepath.Join(s.root, filepath.FromSlash(relativePath.String))
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return true, fmt.Errorf("remove unreferenced external blob: %w", err)
		}
		_ = syncDirectory(filepath.Dir(path))
	}
	return true, nil
}

// ReconcileGarbage marks currently unreferenced blobs for a later sweep and
// clears marks from blobs that became referenced before the grace period ended.
func (s *Store) ReconcileGarbage(ctx context.Context, deleteAfter time.Time) (GarbageStats, error) {
	if s == nil || s.database == nil || deleteAfter.IsZero() {
		return GarbageStats{}, fmt.Errorf("blob store and garbage deadline are required")
	}
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return GarbageStats{}, fmt.Errorf("begin blob garbage reconciliation: %w", err)
	}
	defer tx.Rollback()
	unmarked, err := tx.ExecContext(ctx, `
UPDATE encrypted_blobs SET delete_after = NULL
WHERE delete_after IS NOT NULL AND (`+durableReferencePredicate+`)`)
	if err != nil {
		return GarbageStats{}, fmt.Errorf("unmark referenced blobs: %w", err)
	}
	marked, err := tx.ExecContext(ctx, `
UPDATE encrypted_blobs SET delete_after = ?
WHERE delete_after IS NULL AND NOT (`+durableReferencePredicate+`)`, deleteAfter.UTC().UnixMilli())
	if err != nil {
		return GarbageStats{}, fmt.Errorf("mark unreferenced blobs: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return GarbageStats{}, fmt.Errorf("commit blob garbage reconciliation: %w", err)
	}
	markedCount, _ := marked.RowsAffected()
	unmarkedCount, _ := unmarked.RowsAffected()
	return GarbageStats{Marked: markedCount, Unmarked: unmarkedCount}, nil
}

// SweepGarbage removes a bounded batch after a second authoritative reference
// check. Database deletion is one transaction and each changed directory is
// synced once after commit.
func (s *Store) SweepGarbage(ctx context.Context, before time.Time, limit int) (GarbageStats, error) {
	if s == nil || s.database == nil || before.IsZero() || limit < 1 || limit > 10000 {
		return GarbageStats{}, fmt.Errorf("blob store, sweep deadline, and limit between 1 and 10000 are required")
	}
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return GarbageStats{}, fmt.Errorf("begin marked blob sweep: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
DELETE FROM encrypted_blobs
WHERE id IN (
  SELECT id FROM encrypted_blobs
  WHERE delete_after IS NOT NULL AND delete_after <= ?
  ORDER BY delete_after, id LIMIT ?
)
AND NOT (`+durableReferencePredicate+`)
RETURNING id, ciphertext_size, relative_path`, before.UTC().UnixMilli(), limit)
	if err != nil {
		return GarbageStats{}, fmt.Errorf("delete marked blob batch: %w", err)
	}
	type candidate struct {
		id           string
		size         int64
		relativePath sql.NullString
	}
	deleted := make([]candidate, 0, limit)
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.size, &item.relativePath); err != nil {
			rows.Close()
			return GarbageStats{}, fmt.Errorf("scan deleted blob: %w", err)
		}
		deleted = append(deleted, item)
	}
	if err := rows.Close(); err != nil {
		return GarbageStats{}, fmt.Errorf("close deleted blob rows: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return GarbageStats{}, fmt.Errorf("commit marked blob sweep: %w", err)
	}
	stats := GarbageStats{Deleted: len(deleted)}
	touchedDirectories := make(map[string]struct{})
	var removalErr error
	for _, item := range deleted {
		stats.DeletedBytes += item.size
		if !item.relativePath.Valid {
			continue
		}
		path := filepath.Join(s.root, filepath.FromSlash(item.relativePath.String))
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			if removalErr == nil {
				removalErr = fmt.Errorf("remove swept external blob %s: %w", item.id, err)
			}
			continue
		}
		touchedDirectories[filepath.Dir(path)] = struct{}{}
	}
	for directory := range touchedDirectories {
		if err := syncDirectory(directory); err != nil && removalErr == nil {
			removalErr = fmt.Errorf("sync swept blob directory: %w", err)
		}
	}
	return stats, removalErr
}

func (s *Store) ReencryptBlobKeyBatch(ctx context.Context, oldKeyIDs []string, limit int) (int, error) {
	if s == nil || s.database == nil || s.keys == nil || len(oldKeyIDs) == 0 {
		return 0, fmt.Errorf("blob store and previous blob key IDs are required")
	}
	if limit < 1 || limit > 1000 {
		return 0, fmt.Errorf("blob re-encryption batch limit must be between 1 and 1000")
	}
	newKey, err := s.keys.Active(keyring.PurposeBlob)
	if err != nil {
		return 0, err
	}
	placeholders := make([]string, len(oldKeyIDs))
	arguments := make([]interface{}, len(oldKeyIDs)+1)
	for index, id := range oldKeyIDs {
		if !validID(id) || id == newKey.ID {
			return 0, fmt.Errorf("invalid previous blob key ID")
		}
		placeholders[index] = "?"
		arguments[index] = id
	}
	arguments[len(arguments)-1] = limit
	rows, err := s.database.QueryContext(ctx, `
SELECT id FROM encrypted_blobs
WHERE key_id IN (`+strings.Join(placeholders, ",")+`)
ORDER BY id LIMIT ?`, arguments...)
	if err != nil {
		return 0, fmt.Errorf("list blobs for data key rotation: %w", err)
	}
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("read blob for data key rotation: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close blob data key rotation list: %w", err)
	}
	for _, id := range ids {
		if err := s.reencryptBlobKey(ctx, id, newKey); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

func (s *Store) reencryptBlobKey(ctx context.Context, id string, newKey keyring.DataKey) error {
	plaintext, record, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	defer wipeBytes(plaintext)
	if record.KeyID == newKey.ID {
		return nil
	}
	sealed, err := envelope.Seal(newKey.Material, plaintext, blobContext(s.keys.InstanceID(), record.Kind, record.ID), s.random)
	if err != nil {
		return fmt.Errorf("seal blob %s with rotated data key: %w", id, err)
	}
	contentKey, err := s.keys.Active(keyring.PurposeContent)
	if err != nil {
		return err
	}
	contentHMAC := sumContentHMAC(contentKey.Material, record.Kind, plaintext)
	result, err := s.database.ExecContext(ctx, `
UPDATE encrypted_blobs
SET key_id = ?, format_version = ?, aad_version = 1, nonce = ?,
    ciphertext_inline = ?, relative_path = NULL, ciphertext_size = ?, content_hmac = ?
WHERE id = ? AND key_id = ?`, newKey.ID, sealed.FormatVersion, sealed.Nonce,
		sealed.Ciphertext, len(sealed.Ciphertext), contentHMAC, record.ID, record.KeyID)
	if err != nil {
		return fmt.Errorf("switch blob %s to rotated data key: %w", id, err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return fmt.Errorf("blob %s changed during data key rotation", id)
	}
	if !record.External {
		return nil
	}
	relative := blobRelativePath(record.ID)
	if err := s.replaceExternalCiphertext(record.ID, sealed.Ciphertext); err != nil {
		return err
	}
	if _, err := s.database.ExecContext(ctx, `
UPDATE encrypted_blobs SET ciphertext_inline = NULL, relative_path = ?
WHERE id = ? AND key_id = ? AND ciphertext_inline IS NOT NULL`, relative, record.ID, newKey.ID); err != nil {
		return fmt.Errorf("restore external storage for rotated blob %s: %w", id, err)
	}
	return nil
}

func (s *Store) replaceExternalCiphertext(id string, ciphertext []byte) error {
	if err := requirePrivateDirectory(s.root); err != nil {
		return err
	}
	directory := filepath.Join(s.root, id[:2])
	if err := requirePrivateDirectory(directory); err != nil {
		return err
	}
	rotationID := s.newID()
	if !validID(rotationID) {
		return fmt.Errorf("blob store ID generator returned an invalid rotation ID")
	}
	temporary := filepath.Join(directory, "."+id+".rotate-"+rotationID+".tmp")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create rotated external blob: %w", err)
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(ciphertext); err != nil {
		return fmt.Errorf("write rotated external blob: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync rotated external blob: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close rotated external blob: %w", err)
	}
	final := filepath.Join(s.root, filepath.FromSlash(blobRelativePath(id)))
	if err := os.Rename(temporary, final); err != nil {
		return fmt.Errorf("activate rotated external blob: %w", err)
	}
	removeTemporary = false
	if err := syncDirectory(directory); err != nil {
		return fmt.Errorf("sync rotated external blob directory: %w", err)
	}
	return nil
}

func (s *Store) writeExternalCiphertext(id string, ciphertext []byte) (string, string, error) {
	if err := requirePrivateDirectory(s.root); err != nil {
		return "", "", err
	}
	relative := blobRelativePath(id)
	directory := filepath.Join(s.root, id[:2])
	createdDirectory := false
	if err := os.Mkdir(directory, 0o700); err == nil {
		createdDirectory = true
	} else if !errors.Is(err, os.ErrExist) {
		return "", "", fmt.Errorf("create blob directory: %w", err)
	}
	if err := requirePrivateDirectory(directory); err != nil {
		return "", "", err
	}
	if createdDirectory {
		if err := syncDirectory(s.root); err != nil {
			_ = os.Remove(directory)
			return "", "", fmt.Errorf("sync blob root directory: %w", err)
		}
	}
	temporary := filepath.Join(directory, "."+id+".tmp")
	final := filepath.Join(s.root, filepath.FromSlash(relative))
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", "", fmt.Errorf("create encrypted blob temporary file: %w", err)
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(ciphertext); err != nil {
		return "", "", fmt.Errorf("write encrypted blob: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", "", fmt.Errorf("sync encrypted blob: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", "", fmt.Errorf("close encrypted blob: %w", err)
	}
	if err := os.Link(temporary, final); err != nil {
		return "", "", fmt.Errorf("publish encrypted blob without overwrite: %w", err)
	}
	if err := os.Remove(temporary); err != nil {
		_ = os.Remove(final)
		return "", "", fmt.Errorf("remove encrypted blob temporary link: %w", err)
	}
	removeTemporary = false
	if err := syncDirectory(directory); err != nil {
		_ = os.Remove(final)
		_ = syncDirectory(directory)
		return "", "", fmt.Errorf("sync encrypted blob directory: %w", err)
	}
	return relative, final, nil
}

func (s *Store) readExternalCiphertext(relative string, expectedSize int) ([]byte, error) {
	path := filepath.Join(s.root, filepath.FromSlash(relative))
	if err := requirePrivateDirectory(s.root); err != nil {
		return nil, err
	}
	if err := requirePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, err := openNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("open external encrypted blob: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat external encrypted blob: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != int64(expectedSize) {
		return nil, ErrInvalidRecord
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(expectedSize)+1))
	if err != nil {
		return nil, fmt.Errorf("read external encrypted blob: %w", err)
	}
	if len(content) != expectedSize {
		return nil, ErrInvalidRecord
	}
	return content, nil
}

func prepareRoot(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve blob root: %w", err)
	}
	if info, err := os.Lstat(absolute); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("blob root must not be a symbolic link")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect blob root: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return "", fmt.Errorf("create blob root: %w", err)
	}
	if err := requirePrivateDirectory(absolute); err != nil {
		return "", err
	}
	return absolute, nil
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect blob directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("blob directory must be a non-symlink directory with mode 0700")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func sumContentHMAC(key [32]byte, kind string, plaintext []byte) []byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("proxyloom-content-hmac-v1\x00"))
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write(plaintext)
	return mac.Sum(nil)
}

func blobContext(instanceID, kind, id string) envelope.Context {
	return envelope.Context{
		InstanceID: instanceID,
		RecordType: "encrypted_blob:" + kind,
		RecordID:   id,
		Field:      "content",
		Version:    1,
	}
}

func blobRelativePath(id string) string {
	return filepath.ToSlash(filepath.Join(id[:2], id+".blob"))
}

func validKind(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func safeRelativePath(value string) bool {
	if value == "" || strings.Contains(value, "\\") || filepath.IsAbs(value) {
		return false
	}
	cleaned := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	return cleaned == value && cleaned != "." && !strings.HasPrefix(cleaned, "../")
}

func nullableString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
