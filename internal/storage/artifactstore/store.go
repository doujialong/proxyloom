package artifactstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/doujialong/proxyloom/internal/crypto/keyring"
	"github.com/doujialong/proxyloom/internal/storage/blobstore"
)

var (
	ErrNotFound     = errors.New("artifact not found")
	ErrUnauthorized = errors.New("invalid publication token")
	ErrConflict     = errors.New("artifact publication conflict")
)

type Options struct {
	Now    func() time.Time
	NewID  func() string
	Random io.Reader
}

type Store struct {
	database *sql.DB
	keys     *keyring.Ring
	blobs    *blobstore.Store
	now      func() time.Time
	newID    func() string
	random   io.Reader
}

type PublishRequest struct {
	SourceID       string
	SnapshotID     string
	ContentBlobID  string
	ContentType    string
	NodeCount      int
	WarningCount   int
	OutputFormat   string
	BuilderVersion string
}

type Artifact struct {
	ID             string
	SourceID       string
	SnapshotID     string
	BuildSequence  int
	ContentBlobID  string
	ContentType    string
	ContentLength  int
	PublicSHA256   string
	NodeCount      int
	WarningCount   int
	OutputFormat   string
	BuilderVersion string
	CreatedAt      time.Time
}

type Credential struct {
	ID        string
	SourceID  string
	Token     string
	CreatedAt time.Time
}

func New(database *sql.DB, keys *keyring.Ring, blobs *blobstore.Store, options Options) (*Store, error) {
	if database == nil || keys == nil || blobs == nil || options.Now == nil || options.NewID == nil || options.Random == nil {
		return nil, fmt.Errorf("artifact store dependencies are required")
	}
	return &Store{database: database, keys: keys, blobs: blobs, now: options.Now, newID: options.NewID, random: options.Random}, nil
}

func (s *Store) Publish(ctx context.Context, request PublishRequest) (Artifact, error) {
	if !validID(request.SourceID) || !validID(request.SnapshotID) || !validID(request.ContentBlobID) {
		return Artifact{}, ErrNotFound
	}
	if request.ContentType == "" || len(request.ContentType) > 128 || request.NodeCount < 0 || request.WarningCount < 0 ||
		request.OutputFormat == "" || len(request.OutputFormat) > 128 || request.BuilderVersion == "" || len(request.BuilderVersion) > 128 {
		return Artifact{}, fmt.Errorf("invalid artifact metadata")
	}
	now := s.now().UTC()
	id := s.newID()
	if !validID(id) {
		return Artifact{}, fmt.Errorf("artifact ID generator returned an invalid ID")
	}
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Artifact{}, fmt.Errorf("begin artifact publication: %w", err)
	}
	defer tx.Rollback()
	var kind string
	var size int
	var digest sql.NullString
	if err := tx.QueryRowContext(ctx, `
SELECT kind, plaintext_size, public_sha256 FROM encrypted_blobs WHERE id = ?`, request.ContentBlobID).Scan(&kind, &size, &digest); errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, ErrNotFound
	} else if err != nil {
		return Artifact{}, fmt.Errorf("read artifact blob metadata: %w", err)
	}
	if kind != "artifact" || !digest.Valid || len(digest.String) != 64 {
		return Artifact{}, fmt.Errorf("%w: artifact blob is not public content", ErrConflict)
	}
	var sequence int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(build_sequence), 0) + 1 FROM artifacts WHERE source_id = ?`, request.SourceID).Scan(&sequence); err != nil {
		return Artifact{}, fmt.Errorf("allocate artifact sequence: %w", err)
	}
	artifact := Artifact{
		ID: id, SourceID: request.SourceID, SnapshotID: request.SnapshotID,
		BuildSequence: sequence, ContentBlobID: request.ContentBlobID, ContentType: request.ContentType,
		ContentLength: size, PublicSHA256: digest.String, NodeCount: request.NodeCount,
		WarningCount: request.WarningCount, OutputFormat: request.OutputFormat,
		BuilderVersion: request.BuilderVersion, CreatedAt: now,
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO artifacts(
  id, source_id, snapshot_id, build_sequence, content_blob_id, content_type,
  content_length, public_sha256, node_count, warning_count,
  output_format, builder_version, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifact.ID, artifact.SourceID, artifact.SnapshotID, artifact.BuildSequence,
		artifact.ContentBlobID, artifact.ContentType, artifact.ContentLength, artifact.PublicSHA256,
		artifact.NodeCount, artifact.WarningCount, artifact.OutputFormat, artifact.BuilderVersion,
		artifact.CreatedAt.UnixMilli(),
	); err != nil {
		return Artifact{}, fmt.Errorf("insert artifact: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO source_publications(source_id, current_artifact_id, published_at, updated_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(source_id) DO UPDATE SET
  current_artifact_id = excluded.current_artifact_id,
  published_at = excluded.published_at,
  updated_at = excluded.updated_at`,
		artifact.SourceID, artifact.ID, now.UnixMilli(), now.UnixMilli(),
	); err != nil {
		return Artifact{}, fmt.Errorf("switch current artifact: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Artifact{}, fmt.Errorf("commit artifact publication: %w", err)
	}
	return artifact, nil
}

func (s *Store) CreateCredential(ctx context.Context, sourceID string) (Credential, error) {
	if !validID(sourceID) {
		return Credential{}, ErrNotFound
	}
	id := s.newID()
	if !validID(id) {
		return Credential{}, fmt.Errorf("publication token ID generator returned an invalid ID")
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(s.random, secret); err != nil {
		return Credential{}, fmt.Errorf("generate publication token: %w", err)
	}
	encodedSecret := base64.RawURLEncoding.EncodeToString(secret)
	for index := range secret {
		secret[index] = 0
	}
	token := id + "." + encodedSecret
	digest, err := s.tokenHMAC(id, encodedSecret)
	if err != nil {
		return Credential{}, err
	}
	now := s.now().UTC()
	result, err := s.database.ExecContext(ctx, `
INSERT INTO publication_tokens(id, source_id, token_hmac, created_at)
SELECT ?, id, ?, ? FROM sources WHERE id = ? AND lifecycle_state = 'active'`,
		id, digest, now.UnixMilli(), sourceID,
	)
	if err != nil {
		return Credential{}, fmt.Errorf("store publication token: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return Credential{}, ErrNotFound
	}
	return Credential{ID: id, SourceID: sourceID, Token: token, CreatedAt: now}, nil
}

func (s *Store) Resolve(ctx context.Context, token string) (Artifact, error) {
	id, secret, ok := strings.Cut(token, ".")
	if !ok || !validID(id) || len(secret) != 43 {
		return Artifact{}, ErrUnauthorized
	}
	want, err := s.tokenHMAC(id, secret)
	if err != nil {
		return Artifact{}, err
	}
	var sourceID string
	var stored []byte
	var revoked sql.NullInt64
	if err := s.database.QueryRowContext(ctx, `
SELECT source_id, token_hmac, revoked_at FROM publication_tokens WHERE id = ?`, id).Scan(&sourceID, &stored, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Artifact{}, ErrUnauthorized
		}
		return Artifact{}, fmt.Errorf("read publication token: %w", err)
	}
	if revoked.Valid || len(stored) != 32 || subtle.ConstantTimeCompare(stored, want) != 1 {
		return Artifact{}, ErrUnauthorized
	}
	artifact, err := scanArtifact(s.database.QueryRowContext(ctx, `
SELECT a.id, a.source_id, a.snapshot_id, a.build_sequence, a.content_blob_id,
       a.content_type, a.content_length, a.public_sha256, a.node_count,
       a.warning_count, a.output_format, a.builder_version, a.created_at
FROM source_publications p
JOIN artifacts a ON a.id = p.current_artifact_id AND a.source_id = p.source_id
WHERE p.source_id = ?`, sourceID))
	if errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	if err != nil {
		return Artifact{}, fmt.Errorf("read current artifact: %w", err)
	}
	return artifact, nil
}

func (s *Store) Current(ctx context.Context, sourceID string) (Artifact, error) {
	if !validID(sourceID) {
		return Artifact{}, ErrNotFound
	}
	artifact, err := scanArtifact(s.database.QueryRowContext(ctx, `
SELECT a.id, a.source_id, a.snapshot_id, a.build_sequence, a.content_blob_id,
       a.content_type, a.content_length, a.public_sha256, a.node_count,
       a.warning_count, a.output_format, a.builder_version, a.created_at
FROM source_publications p
JOIN artifacts a ON a.id = p.current_artifact_id AND a.source_id = p.source_id
WHERE p.source_id = ?`, sourceID))
	if errors.Is(err, sql.ErrNoRows) {
		return Artifact{}, ErrNotFound
	}
	if err != nil {
		return Artifact{}, fmt.Errorf("read current artifact: %w", err)
	}
	return artifact, nil
}

func (s *Store) Content(ctx context.Context, artifact Artifact) ([]byte, error) {
	content, record, err := s.blobs.Get(ctx, artifact.ContentBlobID)
	if err != nil {
		return nil, err
	}
	if record.Kind != "artifact" || record.PublicSHA256 != artifact.PublicSHA256 || len(content) != artifact.ContentLength {
		return nil, fmt.Errorf("%w: artifact blob metadata differs", ErrConflict)
	}
	return content, nil
}

func (s *Store) tokenHMAC(id, secret string) ([]byte, error) {
	key, err := s.keys.Active(keyring.PurposeToken)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key.Material[:])
	mac.Write([]byte("proxyloom-publication-token-v1\x00"))
	mac.Write([]byte(id))
	mac.Write([]byte{0})
	mac.Write([]byte(secret))
	return mac.Sum(nil), nil
}

type scanner interface {
	Scan(dest ...interface{}) error
}

func scanArtifact(row scanner) (Artifact, error) {
	var artifact Artifact
	var createdAt int64
	if err := row.Scan(
		&artifact.ID, &artifact.SourceID, &artifact.SnapshotID, &artifact.BuildSequence,
		&artifact.ContentBlobID, &artifact.ContentType, &artifact.ContentLength,
		&artifact.PublicSHA256, &artifact.NodeCount, &artifact.WarningCount,
		&artifact.OutputFormat, &artifact.BuilderVersion, &createdAt,
	); err != nil {
		return Artifact{}, err
	}
	artifact.CreatedAt = time.UnixMilli(createdAt).UTC()
	return artifact, nil
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
