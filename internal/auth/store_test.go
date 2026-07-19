package auth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/doujialong/proxyloom/internal/auth"
	"github.com/doujialong/proxyloom/internal/crypto/masterkey"
	storagesqlite "github.com/doujialong/proxyloom/internal/storage/sqlite"
	"github.com/google/uuid"
)

func TestAdministratorBootstrapSessionAndRecovery(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 18, 6, 0, 0, 0, time.UTC)
	database, store := openAdministratorStore(t, &now)
	defer database.Close()

	required, err := store.SetupRequired(ctx)
	if err != nil || !required {
		t.Fatalf("SetupRequired() = %v, %v", required, err)
	}
	setupToken, expires, err := store.CreateSetupToken(ctx, 0)
	if err != nil || setupToken == "" || !expires.Equal(now.Add(auth.DefaultSetupTTL)) {
		t.Fatalf("CreateSetupToken() token=%q expires=%s error=%v", setupToken, expires, err)
	}
	session, err := store.Bootstrap(ctx, setupToken, "administrator", "correct horse battery staple", "Asia/Shanghai", "setup-1", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if session.Token == "" || session.CSRFToken == "" || session.Administrator.Username != "administrator" {
		t.Fatalf("bootstrap session = %+v", session)
	}
	if _, err := store.Bootstrap(ctx, setupToken, "second-admin", "correct horse battery staple", "UTC", "setup-2", "127.0.0.1"); !errors.Is(err, auth.ErrSetupAlreadyComplete) {
		t.Fatalf("reused setup token error = %v", err)
	}
	if _, _, err := store.CreateSetupToken(ctx, 0); !errors.Is(err, auth.ErrSetupAlreadyComplete) {
		t.Fatalf("post-setup token error = %v", err)
	}

	authenticated, err := store.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyCSRF(authenticated, session.CSRFToken); err != nil {
		t.Fatalf("VerifyCSRF() error = %v", err)
	}
	if err := store.VerifyCSRF(authenticated, "plcsrf1_invalid"); !errors.Is(err, auth.ErrInvalidCSRF) {
		t.Fatalf("invalid CSRF error = %v", err)
	}
	if err := store.RequireRecent(authenticated); err != nil {
		t.Fatalf("RequireRecent() initial error = %v", err)
	}

	now = now.Add(auth.RecentAuthenticationTTL + time.Second)
	if err := store.RequireRecent(authenticated); !errors.Is(err, auth.ErrRecentAuthenticationRequired) {
		t.Fatalf("stale recent authentication error = %v", err)
	}
	if _, err := store.Reauthenticate(ctx, authenticated, "wrong password", "reauth-bad", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong reauthentication error = %v", err)
	}
	if _, err := store.Reauthenticate(ctx, authenticated, "correct horse battery staple", "reauth-good", "127.0.0.1"); err != nil {
		t.Fatalf("Reauthenticate() error = %v", err)
	}

	loggedIn, err := store.Login(ctx, "ADMINISTRATOR", "correct horse battery staple", "login-good", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Login(ctx, "missing", "wrong password", "login-missing", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("unknown login error = %v", err)
	}
	if err := store.ChangePassword(ctx, authenticated, "wrong password", "replacement", "change-bad", "127.0.0.1"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong current password change error = %v", err)
	}
	if err := store.ChangePassword(ctx, authenticated, "correct horse battery staple", "", "change-empty", "127.0.0.1"); err == nil {
		t.Fatal("empty replacement password was accepted")
	}
	if err := store.ChangePassword(ctx, authenticated, "correct horse battery staple", "changed password", "change-good", "127.0.0.1"); err != nil {
		t.Fatalf("ChangePassword() error = %v", err)
	}
	for name, token := range map[string]string{"bootstrap": session.Token, "login": loggedIn.Token} {
		if _, err := store.Authenticate(ctx, token); !errors.Is(err, auth.ErrInvalidSession) {
			t.Fatalf("%s session survived password change: %v", name, err)
		}
	}
	changedSession, err := store.Login(ctx, "administrator", "changed password", "login-changed", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, changedSession.Token); err != nil {
		t.Fatal(err)
	}
	if err := store.ResetPassword(ctx, "administrator", "new correct horse battery staple", "recover-1"); err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{"changed": changedSession.Token} {
		if _, err := store.Authenticate(ctx, token); !errors.Is(err, auth.ErrInvalidSession) {
			t.Fatalf("%s session survived password recovery: %v", name, err)
		}
	}
	newSession, err := store.Login(ctx, "administrator", "new correct horse battery staple", "login-new", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	newAuthenticated, err := store.Authenticate(ctx, newSession.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, newAuthenticated, "logout", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, newSession.Token); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("revoked session error = %v", err)
	}

	var audits int
	if err := database.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&audits); err != nil || audits < 7 {
		t.Fatalf("audit count = %d, %v", audits, err)
	}
	if _, err := database.Exec(`UPDATE audit_events SET result = 'failure'`); err == nil {
		t.Fatal("audit event update was not rejected")
	}
}

func TestSetupTokenExpiryAndPasswordHashValidation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 18, 7, 0, 0, 0, time.UTC)
	database, store := openAdministratorStore(t, &now)
	defer database.Close()
	token, _, err := store.CreateSetupToken(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := store.Bootstrap(ctx, token, "administrator", "correct horse battery staple", "UTC", "expired", ""); !errors.Is(err, auth.ErrInvalidSetupToken) {
		t.Fatalf("expired setup token error = %v", err)
	}
	if _, err := auth.HashPassword("1", rand.Reader, auth.DefaultPasswordParams()); err != nil {
		t.Fatalf("one-byte password was rejected: %v", err)
	}
	if _, err := auth.HashPassword("", rand.Reader, auth.DefaultPasswordParams()); err == nil {
		t.Fatal("empty password was accepted")
	}
	if _, err := auth.VerifyPassword("not-a-hash", "password"); !errors.Is(err, auth.ErrInvalidPasswordHash) {
		t.Fatalf("malformed password hash error = %v", err)
	}
}

func TestAdministratorBootstrapAcceptsOneBytePassword(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC)
	database, store := openAdministratorStore(t, &now)
	defer database.Close()
	token, _, err := store.CreateSetupToken(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Bootstrap(ctx, token, "adm", "1", "Asia/Shanghai", "short-setup", "127.0.0.1")
	if err != nil {
		t.Fatalf("one-byte administrator password was rejected: %v", err)
	}
	if session.Administrator.Username != "adm" {
		t.Fatalf("administrator username = %q", session.Administrator.Username)
	}
	if _, err := store.Login(ctx, "adm", "1", "short-login", "127.0.0.1"); err != nil {
		t.Fatalf("one-byte administrator password could not log in: %v", err)
	}
}

func openAdministratorStore(t *testing.T, now *time.Time) (*sql.DB, *auth.Store) {
	t.Helper()
	database, err := sql.Open(storagesqlite.DriverName, filepath.Join(t.TempDir(), "proxyloom.db"))
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	if _, err := database.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		t.Fatal(err)
	}
	if err := storagesqlite.Migrate(context.Background(), database, storagesqlite.MigrateOptions{Now: func() time.Time { return *now }}); err != nil {
		t.Fatal(err)
	}
	var master masterkey.Key
	master.ID = "00000000-0000-4000-8000-000000000001"
	copy(master.Material[:], bytes.Repeat([]byte{0x42}, 32))
	ring, err := storagesqlite.BootstrapKeys(context.Background(), database, master, storagesqlite.KeyBootstrapOptions{
		Now: *now, Random: rand.Reader, NewID: func() string { return uuid.New().String() },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ring.Close)
	store, err := auth.NewStore(database, ring, auth.StoreOptions{
		Now: func() time.Time { return *now }, Random: rand.Reader,
		NewID: func() string { return uuid.New().String() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return database, store
}
