package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/doujialong/proxyloom/internal/crypto/keyring"
)

const (
	setupTokenPrefix        = "plst1_"
	sessionTokenPrefix      = "plss1_"
	csrfTokenPrefix         = "plcsrf1_"
	tokenBytes              = 32
	DefaultSetupTTL         = 24 * time.Hour
	DefaultSessionTTL       = 24 * time.Hour
	RecentAuthenticationTTL = 5 * time.Minute
)

var (
	ErrSetupAlreadyComplete         = errors.New("administrator setup is already complete")
	ErrInvalidSetupToken            = errors.New("invalid or expired setup token")
	ErrInvalidCredentials           = errors.New("invalid credentials")
	ErrInvalidSession               = errors.New("invalid or expired administrator session")
	ErrInvalidCSRF                  = errors.New("invalid CSRF token")
	ErrRecentAuthenticationRequired = errors.New("recent administrator authentication is required")
)

type StoreOptions struct {
	Now        func() time.Time
	Random     io.Reader
	NewID      func() string
	SessionTTL time.Duration
}

type Store struct {
	database   *sql.DB
	keys       *keyring.Ring
	now        func() time.Time
	random     io.Reader
	newID      func() string
	sessionTTL time.Duration
}

type Administrator struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Timezone     string `json:"timezone"`
	SessionEpoch int
	Status       string
}

type Session struct {
	ID              string
	Administrator   Administrator
	Token           string
	CSRFToken       string
	ExpiresAt       time.Time
	RecentAuthUntil time.Time
}

type AuthenticatedSession struct {
	ID            string
	Administrator Administrator
	KeyID         string
	CSRFHMAC      []byte
	ExpiresAt     time.Time
	RecentAuthAt  time.Time
}

type AuditEvent struct {
	ActorType     string
	ActorID       string
	Action        string
	ResourceType  string
	ResourceID    string
	Result        string
	CorrelationID string
	ClientAddress string
	Details       map[string]interface{}
}

func NewStore(database *sql.DB, keys *keyring.Ring, options StoreOptions) (*Store, error) {
	if database == nil || keys == nil || options.Now == nil || options.NewID == nil {
		return nil, fmt.Errorf("administrator store dependencies are required")
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.SessionTTL <= 0 {
		options.SessionTTL = DefaultSessionTTL
	}
	return &Store{database: database, keys: keys, now: options.Now, random: options.Random, newID: options.NewID, sessionTTL: options.SessionTTL}, nil
}

func (s *Store) SetupRequired(ctx context.Context) (bool, error) {
	var count int
	if err := s.database.QueryRowContext(ctx, `SELECT count(*) FROM administrators`).Scan(&count); err != nil {
		return false, fmt.Errorf("inspect administrator setup: %w", err)
	}
	return count == 0, nil
}

func (s *Store) CreateSetupToken(ctx context.Context, ttl time.Duration) (string, time.Time, error) {
	required, err := s.SetupRequired(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	if !required {
		return "", time.Time{}, ErrSetupAlreadyComplete
	}
	if ttl <= 0 || ttl > DefaultSetupTTL {
		ttl = DefaultSetupTTL
	}
	id, err := s.nextID("setup token")
	if err != nil {
		return "", time.Time{}, err
	}
	token, err := s.randomToken(setupTokenPrefix, id)
	if err != nil {
		return "", time.Time{}, err
	}
	key, digest, err := s.tokenDigest(token)
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.now().UTC()
	expires := now.Add(ttl)
	if _, err := s.database.ExecContext(ctx, `
INSERT INTO setup_tokens(id, key_id, token_hmac, created_at, expires_at)
VALUES (?, ?, ?, ?, ?)`, id, key.ID, digest, now.UnixMilli(), expires.UnixMilli()); err != nil {
		return "", time.Time{}, fmt.Errorf("persist setup token: %w", err)
	}
	return token, expires, nil
}

func (s *Store) Bootstrap(ctx context.Context, setupToken, username, password, timezone, correlationID, clientAddress string) (Session, error) {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 64 || !utf8.ValidString(username) {
		return Session{}, fmt.Errorf("administrator username must contain 3 to 64 UTF-8 bytes")
	}
	if timezone == "" {
		timezone = "UTC"
	}
	if len(timezone) > 64 {
		return Session{}, fmt.Errorf("administrator timezone exceeds 64 bytes")
	}
	passwordHash, err := HashPassword(password, s.random, DefaultPasswordParams())
	if err != nil {
		return Session{}, err
	}
	params, _ := json.Marshal(DefaultPasswordParams())
	tokenID, err := parseBoundToken(setupToken, setupTokenPrefix)
	if err != nil {
		return Session{}, ErrInvalidSetupToken
	}
	now := s.now().UTC()
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, fmt.Errorf("begin administrator setup: %w", err)
	}
	defer tx.Rollback()
	var adminCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM administrators`).Scan(&adminCount); err != nil {
		return Session{}, fmt.Errorf("inspect administrator setup: %w", err)
	}
	if adminCount != 0 {
		return Session{}, ErrSetupAlreadyComplete
	}
	var keyID string
	var expected []byte
	var expiresAt int64
	var usedAt sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
SELECT key_id, token_hmac, expires_at, used_at FROM setup_tokens WHERE id = ?`, tokenID).Scan(&keyID, &expected, &expiresAt, &usedAt); errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrInvalidSetupToken
	} else if err != nil {
		return Session{}, fmt.Errorf("read setup token: %w", err)
	}
	key, err := s.keys.ByID(keyID)
	if err != nil {
		return Session{}, ErrInvalidSetupToken
	}
	actual := keyedDigest(key.Material[:], "setup-token", setupToken)
	if usedAt.Valid || now.UnixMilli() >= expiresAt || subtle.ConstantTimeCompare(actual, expected) != 1 {
		return Session{}, ErrInvalidSetupToken
	}
	adminID, err := s.nextID("administrator")
	if err != nil {
		return Session{}, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO administrators(
  id, username, password_hash, password_params, session_epoch,
  status, timezone, created_at, updated_at, last_login_at
) VALUES (?, ?, ?, ?, 1, 'active', ?, ?, ?, ?)`,
		adminID, username, passwordHash, string(params), timezone,
		now.UnixMilli(), now.UnixMilli(), now.UnixMilli()); err != nil {
		return Session{}, fmt.Errorf("create administrator: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE setup_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL`, now.UnixMilli(), tokenID); err != nil {
		return Session{}, fmt.Errorf("consume setup token: %w", err)
	}
	admin := Administrator{ID: adminID, Username: username, Timezone: timezone, SessionEpoch: 1, Status: "active"}
	session, err := s.createSessionTx(ctx, tx, admin, now)
	if err != nil {
		return Session{}, err
	}
	if err := s.insertAuditTx(ctx, tx, AuditEvent{
		ActorType: "setup", ActorID: adminID, Action: "administrator.bootstrap",
		ResourceType: "administrator", ResourceID: adminID, Result: "success",
		CorrelationID: correlationID, ClientAddress: clientAddress,
	}); err != nil {
		return Session{}, err
	}
	if err := tx.Commit(); err != nil {
		return Session{}, fmt.Errorf("commit administrator setup: %w", err)
	}
	return session, nil
}

func (s *Store) Login(ctx context.Context, username, password, correlationID, clientAddress string) (Session, error) {
	username = strings.TrimSpace(username)
	var admin Administrator
	var passwordHash string
	err := s.database.QueryRowContext(ctx, `
SELECT id, username, timezone, session_epoch, status, password_hash
FROM administrators WHERE username = ? COLLATE NOCASE`, username).Scan(
		&admin.ID, &admin.Username, &admin.Timezone, &admin.SessionEpoch, &admin.Status, &passwordHash)
	found := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Session{}, fmt.Errorf("read administrator credentials: %w", err)
	}
	if !found {
		passwordHash = dummyPasswordHash
	}
	matched, verifyErr := VerifyPassword(passwordHash, password)
	if verifyErr != nil {
		return Session{}, fmt.Errorf("verify administrator password: %w", verifyErr)
	}
	if !found || !matched || admin.Status != "active" {
		_ = s.InsertAudit(ctx, AuditEvent{
			ActorType: "system", Action: "session.login", Result: "denied",
			CorrelationID: correlationID, ClientAddress: clientAddress,
		})
		return Session{}, ErrInvalidCredentials
	}
	now := s.now().UTC()
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, fmt.Errorf("begin administrator login: %w", err)
	}
	defer tx.Rollback()
	session, err := s.createSessionTx(ctx, tx, admin, now)
	if err != nil {
		return Session{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE administrators SET last_login_at = ?, updated_at = ? WHERE id = ?`, now.UnixMilli(), now.UnixMilli(), admin.ID); err != nil {
		return Session{}, fmt.Errorf("record administrator login: %w", err)
	}
	if err := s.insertAuditTx(ctx, tx, AuditEvent{
		ActorType: "administrator", ActorID: admin.ID, Action: "session.login",
		ResourceType: "administrator", ResourceID: admin.ID, Result: "success",
		CorrelationID: correlationID, ClientAddress: clientAddress,
	}); err != nil {
		return Session{}, err
	}
	if err := tx.Commit(); err != nil {
		return Session{}, fmt.Errorf("commit administrator login: %w", err)
	}
	return session, nil
}

func (s *Store) Authenticate(ctx context.Context, token string) (AuthenticatedSession, error) {
	id, err := parseBoundToken(token, sessionTokenPrefix)
	if err != nil {
		return AuthenticatedSession{}, ErrInvalidSession
	}
	var session AuthenticatedSession
	var expected []byte
	var epoch int
	var expiresAt, recentAuthAt int64
	var revokedAt sql.NullInt64
	err = s.database.QueryRowContext(ctx, `
SELECT s.id, s.key_id, s.token_hmac, s.expires_at, s.recent_auth_at, s.revoked_at,
       a.id, a.username, a.timezone, a.session_epoch, a.status, s.session_epoch,
       s.csrf_hmac
FROM sessions s JOIN administrators a ON a.id = s.administrator_id
WHERE s.id = ?`, id).Scan(
		&session.ID, &session.KeyID, &expected, &expiresAt, &recentAuthAt, &revokedAt,
		&session.Administrator.ID, &session.Administrator.Username, &session.Administrator.Timezone,
		&session.Administrator.SessionEpoch, &session.Administrator.Status, &epoch, &session.CSRFHMAC)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthenticatedSession{}, ErrInvalidSession
	}
	if err != nil {
		return AuthenticatedSession{}, fmt.Errorf("read administrator session: %w", err)
	}
	key, err := s.keys.ByID(session.KeyID)
	if err != nil {
		return AuthenticatedSession{}, ErrInvalidSession
	}
	actual := keyedDigest(key.Material[:], "session-token", token)
	now := s.now().UTC()
	if revokedAt.Valid || now.UnixMilli() >= expiresAt || epoch != session.Administrator.SessionEpoch ||
		session.Administrator.Status != "active" || subtle.ConstantTimeCompare(actual, expected) != 1 {
		return AuthenticatedSession{}, ErrInvalidSession
	}
	session.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	session.RecentAuthAt = time.UnixMilli(recentAuthAt).UTC()
	return session, nil
}

func (s *Store) VerifyCSRF(session AuthenticatedSession, token string) error {
	if token == "" || !strings.HasPrefix(token, csrfTokenPrefix) {
		return ErrInvalidCSRF
	}
	key, err := s.keys.ByID(session.KeyID)
	if err != nil {
		return ErrInvalidCSRF
	}
	actual := keyedDigest(key.Material[:], "csrf-token", token)
	if subtle.ConstantTimeCompare(actual, session.CSRFHMAC) != 1 {
		return ErrInvalidCSRF
	}
	return nil
}

func (s *Store) RotateCSRF(ctx context.Context, session AuthenticatedSession) (string, error) {
	secret := make([]byte, tokenBytes)
	if _, err := io.ReadFull(s.random, secret); err != nil {
		return "", fmt.Errorf("generate CSRF token: %w", err)
	}
	csrf := csrfTokenPrefix + base64.RawURLEncoding.EncodeToString(secret)
	wipe(secret)
	key, err := s.keys.ByID(session.KeyID)
	if err != nil {
		return "", ErrInvalidSession
	}
	digest := keyedDigest(key.Material[:], "csrf-token", csrf)
	result, err := s.database.ExecContext(ctx, `
UPDATE sessions SET csrf_hmac = ? WHERE id = ? AND revoked_at IS NULL`, digest, session.ID)
	if err != nil {
		return "", fmt.Errorf("rotate CSRF token: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return "", ErrInvalidSession
	}
	return csrf, nil
}

func (s *Store) Reauthenticate(ctx context.Context, session AuthenticatedSession, password, correlationID, clientAddress string) (time.Time, error) {
	var passwordHash string
	if err := s.database.QueryRowContext(ctx, `SELECT password_hash FROM administrators WHERE id = ?`, session.Administrator.ID).Scan(&passwordHash); err != nil {
		return time.Time{}, ErrInvalidCredentials
	}
	matched, err := VerifyPassword(passwordHash, password)
	if err != nil || !matched {
		_ = s.InsertAudit(ctx, AuditEvent{
			ActorType: "administrator", ActorID: session.Administrator.ID,
			Action: "session.reauthenticate", Result: "denied",
			CorrelationID: correlationID, ClientAddress: clientAddress,
		})
		return time.Time{}, ErrInvalidCredentials
	}
	now := s.now().UTC()
	if _, err := s.database.ExecContext(ctx, `
UPDATE sessions SET recent_auth_at = ? WHERE id = ? AND revoked_at IS NULL`, now.UnixMilli(), session.ID); err != nil {
		return time.Time{}, fmt.Errorf("update recent authentication: %w", err)
	}
	_ = s.InsertAudit(ctx, AuditEvent{
		ActorType: "administrator", ActorID: session.Administrator.ID,
		Action: "session.reauthenticate", Result: "success",
		CorrelationID: correlationID, ClientAddress: clientAddress,
	})
	return now.Add(RecentAuthenticationTTL), nil
}

func (s *Store) ChangePassword(ctx context.Context, session AuthenticatedSession, currentPassword, newPassword, correlationID, clientAddress string) error {
	var currentHash string
	if err := s.database.QueryRowContext(ctx, `SELECT password_hash FROM administrators WHERE id = ? AND status = 'active'`, session.Administrator.ID).Scan(&currentHash); err != nil {
		return ErrInvalidCredentials
	}
	matched, err := VerifyPassword(currentHash, currentPassword)
	if err != nil || !matched {
		_ = s.InsertAudit(ctx, AuditEvent{
			ActorType: "administrator", ActorID: session.Administrator.ID,
			Action: "administrator.password_change", ResourceType: "administrator", ResourceID: session.Administrator.ID,
			Result: "denied", CorrelationID: correlationID, ClientAddress: clientAddress,
		})
		return ErrInvalidCredentials
	}
	newHash, err := HashPassword(newPassword, s.random, DefaultPasswordParams())
	if err != nil {
		return err
	}
	now := s.now().UTC()
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin administrator password change: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
UPDATE administrators SET password_hash = ?, session_epoch = session_epoch + 1, updated_at = ?
WHERE id = ? AND status = 'active' AND session_epoch = ?`,
		newHash, now.UnixMilli(), session.Administrator.ID, session.Administrator.SessionEpoch)
	if err != nil {
		return fmt.Errorf("change administrator password: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return ErrInvalidSession
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE administrator_id = ? AND revoked_at IS NULL`, now.UnixMilli(), session.Administrator.ID); err != nil {
		return fmt.Errorf("revoke sessions after password change: %w", err)
	}
	if err := s.insertAuditTx(ctx, tx, AuditEvent{
		ActorType: "administrator", ActorID: session.Administrator.ID,
		Action: "administrator.password_change", ResourceType: "administrator", ResourceID: session.Administrator.ID,
		Result: "success", CorrelationID: correlationID, ClientAddress: clientAddress,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit administrator password change: %w", err)
	}
	return nil
}

func (s *Store) RequireRecent(session AuthenticatedSession) error {
	if s.now().UTC().After(session.RecentAuthAt.Add(RecentAuthenticationTTL)) {
		return ErrRecentAuthenticationRequired
	}
	return nil
}

func (s *Store) Revoke(ctx context.Context, session AuthenticatedSession, correlationID, clientAddress string) error {
	now := s.now().UTC()
	if _, err := s.database.ExecContext(ctx, `
UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now.UnixMilli(), session.ID); err != nil {
		return fmt.Errorf("revoke administrator session: %w", err)
	}
	return s.InsertAudit(ctx, AuditEvent{
		ActorType: "administrator", ActorID: session.Administrator.ID,
		Action: "session.logout", ResourceType: "session", ResourceID: session.ID,
		Result: "success", CorrelationID: correlationID, ClientAddress: clientAddress,
	})
}

func (s *Store) ResetPassword(ctx context.Context, username, newPassword, correlationID string) error {
	hash, err := HashPassword(newPassword, s.random, DefaultPasswordParams())
	if err != nil {
		return err
	}
	now := s.now().UTC()
	tx, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin administrator recovery: %w", err)
	}
	defer tx.Rollback()
	var adminID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM administrators WHERE username = ? COLLATE NOCASE`, strings.TrimSpace(username)).Scan(&adminID); errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidCredentials
	} else if err != nil {
		return fmt.Errorf("read recovery administrator: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE administrators SET password_hash = ?, session_epoch = session_epoch + 1, updated_at = ? WHERE id = ?`, hash, now.UnixMilli(), adminID); err != nil {
		return fmt.Errorf("reset administrator password: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE administrator_id = ? AND revoked_at IS NULL`, now.UnixMilli(), adminID); err != nil {
		return fmt.Errorf("revoke sessions during recovery: %w", err)
	}
	if err := s.insertAuditTx(ctx, tx, AuditEvent{
		ActorType: "system", Action: "administrator.password_recovery",
		ResourceType: "administrator", ResourceID: adminID, Result: "success",
		CorrelationID: correlationID,
	}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit administrator recovery: %w", err)
	}
	return nil
}

func (s *Store) InsertAudit(ctx context.Context, event AuditEvent) error {
	return s.insertAudit(ctx, s.database, event)
}

func (s *Store) insertAuditTx(ctx context.Context, tx *sql.Tx, event AuditEvent) error {
	return s.insertAudit(ctx, tx, event)
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
}

func (s *Store) insertAudit(ctx context.Context, executor sqlExecutor, event AuditEvent) error {
	if event.ActorType == "" {
		event.ActorType = "system"
	}
	if event.CorrelationID == "" {
		event.CorrelationID = "system-" + s.newID()
	}
	if event.Details == nil {
		event.Details = map[string]interface{}{}
	}
	details, err := json.Marshal(event.Details)
	if err != nil || len(details) > 16384 {
		return fmt.Errorf("audit details are invalid or too large")
	}
	id, err := s.nextID("audit event")
	if err != nil {
		return err
	}
	_, err = executor.ExecContext(ctx, `
INSERT INTO audit_events(
  id, occurred_at, actor_type, actor_id, action, resource_type,
  resource_id, result, correlation_id, client_address, detail_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, s.now().UTC().UnixMilli(), event.ActorType, nullableString(event.ActorID), event.Action,
		nullableString(event.ResourceType), nullableString(event.ResourceID), event.Result,
		event.CorrelationID, nullableString(event.ClientAddress), string(details))
	if err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}

func (s *Store) createSessionTx(ctx context.Context, tx *sql.Tx, admin Administrator, now time.Time) (Session, error) {
	id, err := s.nextID("session")
	if err != nil {
		return Session{}, err
	}
	token, err := s.randomToken(sessionTokenPrefix, id)
	if err != nil {
		return Session{}, err
	}
	csrfSecret := make([]byte, tokenBytes)
	if _, err := io.ReadFull(s.random, csrfSecret); err != nil {
		return Session{}, fmt.Errorf("generate CSRF token: %w", err)
	}
	csrf := csrfTokenPrefix + base64.RawURLEncoding.EncodeToString(csrfSecret)
	wipe(csrfSecret)
	key, tokenDigest, err := s.tokenDigestFor("session-token", token)
	if err != nil {
		return Session{}, err
	}
	csrfDigest := keyedDigest(key.Material[:], "csrf-token", csrf)
	expires := now.Add(s.sessionTTL)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO sessions(
  id, administrator_id, key_id, token_hmac, csrf_hmac, session_epoch,
  created_at, expires_at, last_seen_at, recent_auth_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, admin.ID, key.ID, tokenDigest, csrfDigest, admin.SessionEpoch,
		now.UnixMilli(), expires.UnixMilli(), now.UnixMilli(), now.UnixMilli()); err != nil {
		return Session{}, fmt.Errorf("create administrator session: %w", err)
	}
	return Session{
		ID: id, Administrator: admin, Token: token, CSRFToken: csrf,
		ExpiresAt: expires, RecentAuthUntil: now.Add(RecentAuthenticationTTL),
	}, nil
}

func (s *Store) tokenDigest(token string) (keyring.DataKey, []byte, error) {
	return s.tokenDigestFor("setup-token", token)
}

func (s *Store) tokenDigestFor(domain, token string) (keyring.DataKey, []byte, error) {
	key, err := s.keys.Active(keyring.PurposeToken)
	if err != nil {
		return keyring.DataKey{}, nil, err
	}
	return key, keyedDigest(key.Material[:], domain, token), nil
}

func keyedDigest(key []byte, domain, value string) []byte {
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write([]byte("proxyloom\x00" + domain + "\x00" + value))
	return hash.Sum(nil)
}

func (s *Store) randomToken(prefix, id string) (string, error) {
	secret := make([]byte, tokenBytes)
	if _, err := io.ReadFull(s.random, secret); err != nil {
		return "", fmt.Errorf("generate authentication token: %w", err)
	}
	defer wipe(secret)
	return prefix + id + "." + base64.RawURLEncoding.EncodeToString(secret), nil
}

func parseBoundToken(token, prefix string) (string, error) {
	if !strings.HasPrefix(token, prefix) {
		return "", errors.New("token prefix mismatch")
	}
	parts := strings.Split(strings.TrimPrefix(token, prefix), ".")
	if len(parts) != 2 || len(parts[0]) != 36 {
		return "", errors.New("token shape mismatch")
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(secret) != tokenBytes {
		wipe(secret)
		return "", errors.New("token secret mismatch")
	}
	wipe(secret)
	return parts[0], nil
}

func (s *Store) nextID(kind string) (string, error) {
	id := s.newID()
	if len(id) != 36 {
		return "", fmt.Errorf("%s ID generator returned an invalid ID", kind)
	}
	return id, nil
}

func nullableString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

// This fixed valid hash keeps unknown-user login work comparable to a real password check.
const dummyPasswordHash = "$argon2id$v=19$m=65536,t=3,p=1$MDEyMzQ1Njc4OWFiY2RlZg$cJ1uW6X7fO2D1cM0d9RYl5RkvjhdL2IhLc7sYkYKXGo"
