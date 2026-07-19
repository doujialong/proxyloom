package managedbackup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/doujialong/proxyloom/internal/crypto/masterkey"
	"github.com/doujialong/proxyloom/internal/storage/blobstore"
	storagesqlite "github.com/doujialong/proxyloom/internal/storage/sqlite"
	"github.com/google/uuid"
)

const (
	Format              = "proxyloom-managed-backup-v1"
	manifestName        = "manifest.json"
	keyName             = "recovery-key"
	databaseName        = "database.sqlite"
	maxManifestBytes    = 1 << 20
	maxBackupFileBytes  = int64(8 << 30)
	maxBackupTotalBytes = int64(32 << 30)
)

type FileManifest struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Format        string         `json:"format"`
	CreatedAt     string         `json:"created_at"`
	SchemaVersion int            `json:"schema_version"`
	InstanceID    string         `json:"instance_id"`
	MasterKeyID   string         `json:"master_key_id"`
	Files         []FileManifest `json:"files"`
}

type Info struct {
	Path          string
	SHA256        string
	Size          int64
	SchemaVersion int
	FileCount     int
	CreatedAt     time.Time
}

type Extracted struct {
	Root     string
	Database string
	BlobRoot string
	Master   masterkey.Key
	Manifest Manifest
}

func Create(ctx context.Context, database *sql.DB, dataDir string, master masterkey.Key, passphrase []byte, destination string, now time.Time) (info Info, err error) {
	if database == nil || dataDir == "" || master.ID == "" || destination == "" || now.IsZero() {
		return Info{}, fmt.Errorf("database, data directory, master key, destination and time are required")
	}
	if len(passphrase) < 12 {
		return Info{}, fmt.Errorf("backup passphrase must contain at least 12 bytes")
	}
	var prepared int
	if err := database.QueryRowContext(ctx, `SELECT count(*) FROM master_key_slots WHERE state = 'prepared'`).Scan(&prepared); err != nil {
		return Info{}, fmt.Errorf("inspect master key rotation state: %w", err)
	}
	if prepared != 0 {
		return Info{}, fmt.Errorf("managed backup is unavailable while master key rotation is pending")
	}
	temporaryDB := filepath.Join(dataDir, ".managed-backup-"+uuid.New().String()+".db")
	backup, err := storagesqlite.CreateVerifiedBackup(ctx, database, temporaryDB)
	if err != nil {
		return Info{}, err
	}
	defer os.Remove(temporaryDB)

	backupDB, err := sql.Open(storagesqlite.DriverName, temporaryDB)
	if err != nil {
		return Info{}, fmt.Errorf("open managed backup database: %w", err)
	}
	backupDB.SetMaxOpenConns(1)
	defer backupDB.Close()
	var instanceID, activeMasterID string
	if err := backupDB.QueryRowContext(ctx, `SELECT id, active_master_key_id FROM instances WHERE singleton = 1`).Scan(&instanceID, &activeMasterID); err != nil {
		return Info{}, fmt.Errorf("read backup instance identity: %w", err)
	}
	if activeMasterID != master.ID {
		return Info{}, fmt.Errorf("active database master key does not match the supplied key")
	}

	files := []FileManifest{{Name: databaseName, Size: backup.Size, SHA256: backup.SHA256}}
	paths, err := referencedBlobs(ctx, backupDB)
	if err != nil {
		return Info{}, err
	}
	for _, relative := range paths {
		path := filepath.Join(dataDir, "blobs", filepath.FromSlash(relative))
		entry, err := inspectFile(path, "blobs/"+relative)
		if err != nil {
			return Info{}, err
		}
		files = append(files, entry)
	}
	keyBytes := []byte(masterkey.Encode(master))
	defer wipe(keyBytes)
	keyDigest := sha256.Sum256(keyBytes)
	files = append(files, FileManifest{
		Name: keyName, Size: int64(len(keyBytes)), SHA256: hex.EncodeToString(keyDigest[:]),
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	manifest := Manifest{
		Format: Format, CreatedAt: now.UTC().Format(time.RFC3339Nano),
		SchemaVersion: backup.SchemaVersion, InstanceID: instanceID,
		MasterKeyID: master.ID, Files: files,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return Info{}, fmt.Errorf("encode backup manifest: %w", err)
	}

	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Info{}, fmt.Errorf("create managed backup: %w", err)
	}
	removeOutput := true
	defer func() {
		_ = output.Close()
		if removeOutput {
			_ = os.Remove(destination)
		}
	}()
	hash := sha256.New()
	encrypted, err := newEncryptedWriter(io.MultiWriter(output, hash), passphrase, rand.Reader)
	if err != nil {
		return Info{}, err
	}
	compressed := gzip.NewWriter(encrypted)
	tarWriter := tar.NewWriter(compressed)
	if err := writeTarBytes(tarWriter, manifestName, manifestBytes, now); err != nil {
		return Info{}, err
	}
	if err := writeTarBytes(tarWriter, keyName, keyBytes, now); err != nil {
		return Info{}, err
	}
	if err := writeTarFile(ctx, tarWriter, databaseName, temporaryDB, backup.Size, now); err != nil {
		return Info{}, err
	}
	for _, relative := range paths {
		entryName := "blobs/" + relative
		entry := fileByName(files, entryName)
		if err := writeTarFile(ctx, tarWriter, entryName, filepath.Join(dataDir, "blobs", filepath.FromSlash(relative)), entry.Size, now); err != nil {
			return Info{}, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return Info{}, fmt.Errorf("close managed backup archive: %w", err)
	}
	if err := compressed.Close(); err != nil {
		return Info{}, fmt.Errorf("close managed backup compression: %w", err)
	}
	if err := encrypted.Close(); err != nil {
		return Info{}, err
	}
	if err := output.Sync(); err != nil {
		return Info{}, fmt.Errorf("sync managed backup: %w", err)
	}
	if err := output.Close(); err != nil {
		return Info{}, fmt.Errorf("close managed backup: %w", err)
	}
	stat, err := os.Stat(destination)
	if err != nil {
		return Info{}, fmt.Errorf("stat managed backup: %w", err)
	}
	removeOutput = false
	return Info{
		Path: destination, SHA256: hex.EncodeToString(hash.Sum(nil)), Size: stat.Size(),
		SchemaVersion: backup.SchemaVersion, FileCount: len(files), CreatedAt: now.UTC(),
	}, nil
}

func ExtractAndVerify(ctx context.Context, sourcePath, stagingRoot string, passphrase []byte) (result Extracted, err error) {
	if sourcePath == "" || stagingRoot == "" || len(passphrase) < 12 {
		return Extracted{}, ErrAuthentication
	}
	if err := os.Mkdir(stagingRoot, 0o700); err != nil {
		return Extracted{}, fmt.Errorf("create restore staging directory: %w", err)
	}
	removeStaging := true
	defer func() {
		if removeStaging {
			_ = os.RemoveAll(stagingRoot)
		}
	}()
	blobRoot := filepath.Join(stagingRoot, "blobs")
	if err := os.Mkdir(blobRoot, 0o700); err != nil {
		return Extracted{}, fmt.Errorf("create restore blob directory: %w", err)
	}
	input, err := os.Open(sourcePath)
	if err != nil {
		return Extracted{}, fmt.Errorf("open managed backup: %w", err)
	}
	defer input.Close()
	decrypted, err := newEncryptedReader(input, passphrase)
	if err != nil {
		return Extracted{}, err
	}
	compressed, err := gzip.NewReader(decrypted)
	if err != nil {
		return Extracted{}, ErrAuthentication
	}
	defer compressed.Close()
	tarReader := tar.NewReader(compressed)
	var manifest Manifest
	var masterBytes []byte
	seen := make(map[string]FileManifest)
	var total int64
	entryIndex := 0
	for {
		if err := ctx.Err(); err != nil {
			return Extracted{}, err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Extracted{}, ErrAuthentication
		}
		entryIndex++
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > maxBackupFileBytes {
			return Extracted{}, fmt.Errorf("managed backup contains an invalid file entry")
		}
		total += header.Size
		if total > maxBackupTotalBytes {
			return Extracted{}, fmt.Errorf("managed backup exceeds the restore size limit")
		}
		if entryIndex == 1 {
			if header.Name != manifestName || header.Size > maxManifestBytes {
				return Extracted{}, fmt.Errorf("managed backup manifest is missing")
			}
			content, err := io.ReadAll(io.LimitReader(tarReader, maxManifestBytes+1))
			if err != nil || int64(len(content)) != header.Size || json.Unmarshal(content, &manifest) != nil {
				return Extracted{}, fmt.Errorf("managed backup manifest is invalid")
			}
			if err := validateManifest(manifest); err != nil {
				return Extracted{}, err
			}
			continue
		}
		expected, exists := fileManifestMap(manifest.Files)[header.Name]
		if !exists || expected.Size != header.Size {
			return Extracted{}, fmt.Errorf("managed backup contains an unexpected file %q", header.Name)
		}
		if _, duplicate := seen[header.Name]; duplicate {
			return Extracted{}, fmt.Errorf("managed backup contains duplicate file %q", header.Name)
		}
		if header.Name == keyName {
			if header.Size > masterkey.MaxFileBytes {
				return Extracted{}, fmt.Errorf("managed backup recovery key is invalid")
			}
			masterBytes, err = io.ReadAll(io.LimitReader(tarReader, masterkey.MaxFileBytes+1))
			if err != nil || int64(len(masterBytes)) != header.Size || digestBytes(masterBytes) != expected.SHA256 {
				wipe(masterBytes)
				return Extracted{}, fmt.Errorf("managed backup recovery key failed integrity verification")
			}
			seen[header.Name] = expected
			continue
		}
		destination, err := extractionPath(stagingRoot, header.Name)
		if err != nil {
			return Extracted{}, err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return Extracted{}, fmt.Errorf("create restore directory: %w", err)
		}
		file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return Extracted{}, fmt.Errorf("create restore staging file: %w", err)
		}
		hash := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(file, hash), tarReader)
		syncErr := file.Sync()
		closeErr := file.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
			return Extracted{}, fmt.Errorf("managed backup file %q failed integrity verification", header.Name)
		}
		seen[header.Name] = expected
	}
	if err := compressed.Close(); err != nil {
		return Extracted{}, ErrAuthentication
	}
	if len(seen) != len(manifest.Files) {
		return Extracted{}, fmt.Errorf("managed backup is incomplete")
	}
	master, err := masterkey.Parse(string(masterBytes))
	wipe(masterBytes)
	if err != nil || master.ID != manifest.MasterKeyID {
		return Extracted{}, fmt.Errorf("managed backup recovery key is invalid")
	}
	databasePath := filepath.Join(stagingRoot, databaseName)
	if err := verifyContents(ctx, databasePath, blobRoot, master, manifest); err != nil {
		wipe(master.Material[:])
		return Extracted{}, err
	}
	removeStaging = false
	return Extracted{
		Root: stagingRoot, Database: databasePath, BlobRoot: blobRoot,
		Master: master, Manifest: manifest,
	}, nil
}

func verifyContents(ctx context.Context, databasePath, blobRoot string, master masterkey.Key, manifest Manifest) error {
	store, err := storagesqlite.Open(ctx, databasePath, storagesqlite.OpenOptions{
		Migrate: storagesqlite.MigrateOptions{
			Now: time.Now,
			BeforeUpgrade: func(context.Context, *sql.DB, int, int) error {
				return fmt.Errorf("managed backup schema must match this service before restore")
			},
		},
	})
	if err != nil {
		return fmt.Errorf("verify managed backup database: %w", err)
	}
	defer store.Close()
	version, err := storagesqlite.CurrentVersion(ctx, store.DB())
	if err != nil || version != manifest.SchemaVersion {
		return fmt.Errorf("managed backup schema version is inconsistent")
	}
	ring, err := storagesqlite.LoadKeys(ctx, store.DB(), master)
	if err != nil {
		return fmt.Errorf("verify managed backup encryption: %w", err)
	}
	defer ring.Close()
	if ring.InstanceID() != manifest.InstanceID {
		return fmt.Errorf("managed backup instance identity is inconsistent")
	}
	blobs, err := blobstore.New(store.DB(), ring, blobstore.Options{
		Root: blobRoot, Random: rand.Reader, Now: time.Now, NewID: func() string { return uuid.New().String() },
	})
	if err != nil {
		return err
	}
	rows, err := store.DB().QueryContext(ctx, `SELECT id FROM encrypted_blobs ORDER BY id`)
	if err != nil {
		return fmt.Errorf("list managed backup blobs: %w", err)
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("read managed backup blob ID: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close managed backup blob list: %w", err)
	}
	for _, id := range ids {
		content, _, err := blobs.Get(ctx, id)
		wipe(content)
		if err != nil {
			return fmt.Errorf("verify managed backup blob %s: %w", id, err)
		}
	}
	return nil
}

func referencedBlobs(ctx context.Context, database *sql.DB) ([]string, error) {
	rows, err := database.QueryContext(ctx, `SELECT relative_path FROM encrypted_blobs WHERE relative_path IS NOT NULL ORDER BY relative_path`)
	if err != nil {
		return nil, fmt.Errorf("list external encrypted blobs: %w", err)
	}
	defer rows.Close()
	result := make([]string, 0)
	for rows.Next() {
		var relative string
		if err := rows.Scan(&relative); err != nil {
			return nil, fmt.Errorf("read external encrypted blob path: %w", err)
		}
		if !safeRelative(relative) {
			return nil, fmt.Errorf("database contains an unsafe encrypted blob path")
		}
		result = append(result, relative)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate external encrypted blob paths: %w", err)
	}
	return result, nil
}

func inspectFile(path, name string) (FileManifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return FileManifest{}, fmt.Errorf("open backup file %q: %w", name, err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0o600 || stat.Size() > maxBackupFileBytes {
		return FileManifest{}, fmt.Errorf("backup file %q is not a bounded private regular file", name)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return FileManifest{}, fmt.Errorf("digest backup file %q: %w", name, err)
	}
	return FileManifest{Name: name, Size: stat.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func writeTarBytes(writer *tar.Writer, name string, content []byte, now time.Time) error {
	header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), ModTime: now.UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write backup entry %q: %w", name, err)
	}
	if _, err := writer.Write(content); err != nil {
		return fmt.Errorf("write backup content %q: %w", name, err)
	}
	return nil
}

func writeTarFile(ctx context.Context, writer *tar.Writer, name, path string, size int64, now time.Time) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open backup input %q: %w", name, err)
	}
	defer file.Close()
	header := &tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: now.UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write backup header %q: %w", name, err)
	}
	written, err := io.Copy(writer, &contextReader{ctx: ctx, source: file})
	if err != nil || written != size {
		return fmt.Errorf("write backup file %q: %w", name, err)
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(destination []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(destination)
}

func validateManifest(manifest Manifest) error {
	if manifest.Format != Format || manifest.InstanceID == "" || manifest.MasterKeyID == "" || manifest.SchemaVersion < 1 || len(manifest.Files) < 2 {
		return fmt.Errorf("managed backup manifest is incompatible")
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil {
		return fmt.Errorf("managed backup manifest timestamp is invalid")
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, file := range manifest.Files {
		if (file.Name != keyName && file.Name != databaseName && !strings.HasPrefix(file.Name, "blobs/")) ||
			file.Size < 0 || file.Size > maxBackupFileBytes || len(file.SHA256) != 64 {
			return fmt.Errorf("managed backup manifest contains an invalid file")
		}
		if strings.HasPrefix(file.Name, "blobs/") && !safeRelative(strings.TrimPrefix(file.Name, "blobs/")) {
			return fmt.Errorf("managed backup manifest contains an unsafe path")
		}
		if _, err := hex.DecodeString(file.SHA256); err != nil {
			return fmt.Errorf("managed backup manifest contains an invalid digest")
		}
		if _, duplicate := seen[file.Name]; duplicate {
			return fmt.Errorf("managed backup manifest contains duplicate files")
		}
		seen[file.Name] = struct{}{}
	}
	for _, required := range []string{keyName, databaseName} {
		if _, exists := seen[required]; !exists {
			return fmt.Errorf("managed backup manifest is missing %q", required)
		}
	}
	return nil
}

func extractionPath(root, name string) (string, error) {
	if name == databaseName {
		return filepath.Join(root, databaseName), nil
	}
	if strings.HasPrefix(name, "blobs/") {
		relative := strings.TrimPrefix(name, "blobs/")
		if safeRelative(relative) {
			return filepath.Join(root, "blobs", filepath.FromSlash(relative)), nil
		}
	}
	return "", fmt.Errorf("managed backup contains an unsafe path")
}

func safeRelative(value string) bool {
	if value == "" || filepath.IsAbs(value) || strings.Contains(value, "\\") {
		return false
	}
	cleaned := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	return cleaned == value && cleaned != "." && !strings.HasPrefix(cleaned, "../")
}

func fileByName(files []FileManifest, name string) FileManifest {
	for _, file := range files {
		if file.Name == name {
			return file
		}
	}
	return FileManifest{}
}

func fileManifestMap(files []FileManifest) map[string]FileManifest {
	result := make(map[string]FileManifest, len(files))
	for _, file := range files {
		result[file.Name] = file
	}
	return result
}

func digestBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
