package sqlite

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/doujialong/proxyloom/internal/crypto/envelope"
	"github.com/doujialong/proxyloom/internal/crypto/keyring"
	"github.com/doujialong/proxyloom/internal/crypto/masterkey"
)

const masterKeyCanary = "proxyloom-master-key-canary-v1"

var (
	ErrCryptoAlreadyInitialized = errors.New("crypto store is already initialized")
	ErrCryptoNotInitialized     = errors.New("crypto store is not initialized")
	ErrMasterKeyMismatch        = errors.New("master key ID does not match the active database key")
	ErrMasterKeyRotationPending = errors.New("a master key rotation is already prepared")
)

type KeyBootstrapOptions struct {
	Now    time.Time
	Random io.Reader
	NewID  func() string
}

func BootstrapKeys(ctx context.Context, database *sql.DB, master masterkey.Key, options KeyBootstrapOptions) (*keyring.Ring, error) {
	if database == nil {
		return nil, fmt.Errorf("database is required")
	}
	if master.ID == "" {
		return nil, fmt.Errorf("master key is required")
	}
	if options.Now.IsZero() {
		return nil, fmt.Errorf("bootstrap time is required")
	}
	if options.Random == nil {
		return nil, fmt.Errorf("bootstrap random source is required")
	}
	if options.NewID == nil {
		return nil, fmt.Errorf("bootstrap ID generator is required")
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin crypto bootstrap: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	for _, table := range []string{"instances", "master_key_slots", "data_keys", "master_key_wrappings"} {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			return nil, fmt.Errorf("inspect crypto table %s: %w", table, err)
		}
		if count != 0 {
			return nil, ErrCryptoAlreadyInitialized
		}
	}

	instanceID := options.NewID()
	if instanceID == "" {
		return nil, fmt.Errorf("bootstrap ID generator returned an empty instance ID")
	}
	canaryContext := envelope.Context{
		InstanceID: instanceID,
		RecordType: "master_key_slots",
		RecordID:   master.ID,
		Field:      "canary",
		Version:    1,
	}
	canary, err := envelope.Seal(master.Material, []byte(masterKeyCanary), canaryContext, options.Random)
	if err != nil {
		return nil, fmt.Errorf("seal master key canary: %w", err)
	}
	now := options.Now.UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO master_key_slots(
  id, state, format_version, canary_nonce, canary_ciphertext,
  prepared_at, activated_at
) VALUES (?, 'active', ?, ?, ?, ?, ?)`,
		master.ID, canary.FormatVersion, canary.Nonce, canary.Ciphertext, now, now,
	); err != nil {
		return nil, fmt.Errorf("insert active master key slot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO instances(id, singleton, created_at, crypto_format_version, active_master_key_id)
VALUES (?, 1, ?, 1, ?)`, instanceID, now, master.ID); err != nil {
		return nil, fmt.Errorf("insert instance: %w", err)
	}

	dataKeys := make([]keyring.DataKey, 0, len(keyring.RequiredPurposes()))
	defer func() { wipeDataKeys(dataKeys) }()
	for _, purpose := range keyring.RequiredPurposes() {
		dataKeys = append(dataKeys, keyring.DataKey{
			ID:      options.NewID(),
			Purpose: purpose,
			Status:  keyring.StatusActive,
		})
		key := &dataKeys[len(dataKeys)-1]
		if key.ID == "" {
			return nil, fmt.Errorf("bootstrap ID generator returned an empty data key ID")
		}
		if _, err := io.ReadFull(options.Random, key.Material[:]); err != nil {
			return nil, fmt.Errorf("generate data key for purpose %s: %w", purpose, err)
		}
		wrapContext := dataKeyWrapContext(instanceID, master.ID, key.ID)
		wrapped, err := envelope.Seal(master.Material, key.Material[:], wrapContext, options.Random)
		if err != nil {
			return nil, fmt.Errorf("wrap data key for purpose %s: %w", purpose, err)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO data_keys(id, purpose, status, created_at)
VALUES (?, ?, 'active', ?)`, key.ID, string(key.Purpose), now); err != nil {
			return nil, fmt.Errorf("insert data key for purpose %s: %w", purpose, err)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO master_key_wrappings(
  master_key_id, data_key_id, wrap_version, wrap_nonce,
  wrapped_key, created_at, verified_at
) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			master.ID, key.ID, wrapped.FormatVersion, wrapped.Nonce,
			wrapped.Ciphertext, now, now,
		); err != nil {
			return nil, fmt.Errorf("insert wrapping for purpose %s: %w", purpose, err)
		}
	}

	ring, err := keyring.New(instanceID, dataKeys)
	if err != nil {
		return nil, fmt.Errorf("build bootstrap keyring: %w", err)
	}
	if err := tx.Commit(); err != nil {
		ring.Close()
		return nil, fmt.Errorf("commit crypto bootstrap: %w", err)
	}
	rollback = false
	return ring, nil
}

func LoadKeys(ctx context.Context, database *sql.DB, master masterkey.Key) (*keyring.Ring, error) {
	if database == nil {
		return nil, fmt.Errorf("database is required")
	}
	if master.ID == "" {
		return nil, fmt.Errorf("master key is required")
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin crypto state read: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	var instanceID string
	var activeMasterKeyID string
	err = tx.QueryRowContext(ctx, `
SELECT id, active_master_key_id FROM instances WHERE singleton = 1`).Scan(&instanceID, &activeMasterKeyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCryptoNotInitialized
	}
	if err != nil {
		return nil, fmt.Errorf("read instance crypto state: %w", err)
	}
	activatePrepared := activeMasterKeyID != master.ID

	var state string
	var formatVersion uint32
	var canaryNonce []byte
	var canaryCiphertext []byte
	if err := tx.QueryRowContext(ctx, `
SELECT state, format_version, canary_nonce, canary_ciphertext
FROM master_key_slots WHERE id = ?`, master.ID).Scan(
		&state, &formatVersion, &canaryNonce, &canaryCiphertext,
	); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrMasterKeyMismatch
	} else if err != nil {
		return nil, fmt.Errorf("read active master key slot: %w", err)
	}
	expectedState := "active"
	if activatePrepared {
		expectedState = "prepared"
	}
	if state != expectedState {
		return nil, ErrMasterKeyMismatch
	}
	canary, err := envelope.Open(master.Material, envelope.Envelope{
		FormatVersion: formatVersion,
		Nonce:         canaryNonce,
		Ciphertext:    canaryCiphertext,
	}, envelope.Context{
		InstanceID: instanceID,
		RecordType: "master_key_slots",
		RecordID:   master.ID,
		Field:      "canary",
		Version:    1,
	})
	if err != nil {
		return nil, fmt.Errorf("verify master key canary: %w", err)
	}
	defer wipeBytes(canary)
	if subtle.ConstantTimeCompare(canary, []byte(masterKeyCanary)) != 1 {
		return nil, envelope.ErrIntegrity
	}

	var expectedDataKeys int
	if err := tx.QueryRowContext(ctx, `
SELECT count(*) FROM data_keys WHERE status IN ('active', 'decrypt_only')`).Scan(&expectedDataKeys); err != nil {
		return nil, fmt.Errorf("count data keys requiring wrapping: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
SELECT d.id, d.purpose, d.status, w.wrap_version, w.wrap_nonce, w.wrapped_key
FROM data_keys d
JOIN master_key_wrappings w ON w.data_key_id = d.id
WHERE w.master_key_id = ? AND d.status IN ('active', 'decrypt_only')
ORDER BY d.purpose, d.id`, master.ID)
	if err != nil {
		return nil, fmt.Errorf("read wrapped data keys: %w", err)
	}
	defer rows.Close()
	dataKeys := make([]keyring.DataKey, 0, len(keyring.RequiredPurposes()))
	defer func() { wipeDataKeys(dataKeys) }()
	for rows.Next() {
		var keyID string
		var purpose string
		var status string
		var wrapVersion uint32
		var wrapNonce []byte
		var wrappedKey []byte
		if err := rows.Scan(&keyID, &purpose, &status, &wrapVersion, &wrapNonce, &wrappedKey); err != nil {
			return nil, fmt.Errorf("scan wrapped data key: %w", err)
		}
		plaintext, err := envelope.Open(master.Material, envelope.Envelope{
			FormatVersion: wrapVersion,
			Nonce:         wrapNonce,
			Ciphertext:    wrappedKey,
		}, dataKeyWrapContext(instanceID, master.ID, keyID))
		if err != nil {
			return nil, fmt.Errorf("unwrap data key %s: %w", keyID, err)
		}
		if len(plaintext) != envelope.KeyBytes {
			wipeBytes(plaintext)
			return nil, envelope.ErrIntegrity
		}
		dataKeys = appendZeroizableDataKey(dataKeys, keyring.DataKey{
			ID:      keyID,
			Purpose: keyring.Purpose(purpose),
			Status:  keyring.Status(status),
		})
		copy(dataKeys[len(dataKeys)-1].Material[:], plaintext)
		wipeBytes(plaintext)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate wrapped data keys: %w", err)
	}
	if len(dataKeys) != expectedDataKeys {
		return nil, fmt.Errorf("%w: incomplete data key wrappings", envelope.ErrIntegrity)
	}
	ring, err := keyring.New(instanceID, dataKeys)
	if err != nil {
		return nil, fmt.Errorf("validate loaded keyring: %w", err)
	}
	if err := tx.Commit(); err != nil {
		ring.Close()
		return nil, fmt.Errorf("commit crypto state read: %w", err)
	}
	committed = true
	if activatePrepared {
		activation, err := database.BeginTx(ctx, nil)
		if err != nil {
			ring.Close()
			return nil, fmt.Errorf("begin prepared master key activation: %w", err)
		}
		defer activation.Rollback()
		now := time.Now().UTC().UnixMilli()
		result, err := activation.ExecContext(ctx, `
UPDATE master_key_slots SET state = 'retired', retired_at = ?
WHERE id = ? AND state = 'active'`, now, activeMasterKeyID)
		if err != nil {
			ring.Close()
			return nil, fmt.Errorf("retire previous master key slot: %w", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			ring.Close()
			return nil, ErrMasterKeyMismatch
		}
		result, err = activation.ExecContext(ctx, `
UPDATE master_key_slots SET state = 'active', activated_at = ?
WHERE id = ? AND state = 'prepared'`, now, master.ID)
		if err != nil {
			ring.Close()
			return nil, fmt.Errorf("activate prepared master key slot: %w", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			ring.Close()
			return nil, ErrMasterKeyMismatch
		}
		result, err = activation.ExecContext(ctx, `
UPDATE instances SET active_master_key_id = ?
WHERE singleton = 1 AND active_master_key_id = ?`, master.ID, activeMasterKeyID)
		if err != nil {
			ring.Close()
			return nil, fmt.Errorf("switch active master key pointer: %w", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			ring.Close()
			return nil, ErrMasterKeyMismatch
		}
		if err := activation.Commit(); err != nil {
			ring.Close()
			return nil, fmt.Errorf("commit prepared master key activation: %w", err)
		}
	}
	return ring, nil
}

type MasterKeyRotationOptions struct {
	Now    time.Time
	Random io.Reader
}

type DataKeyRotationOptions struct {
	Now    time.Time
	Random io.Reader
	NewID  func() string
}

type DataKeyRotation struct {
	Active keyring.DataKey
	OldIDs []string
}

func PrepareDataKeyRotation(ctx context.Context, database *sql.DB, master masterkey.Key, purpose keyring.Purpose, options DataKeyRotationOptions) (DataKeyRotation, error) {
	if database == nil || master.ID == "" || purpose != keyring.PurposeBlob {
		return DataKeyRotation{}, fmt.Errorf("blob data key rotation requires a database and active master key")
	}
	if options.Now.IsZero() || options.Random == nil || options.NewID == nil {
		return DataKeyRotation{}, fmt.Errorf("data key rotation time, random source and ID generator are required")
	}
	ring, err := LoadKeys(ctx, database, master)
	if err != nil {
		return DataKeyRotation{}, fmt.Errorf("load data keys before rotation: %w", err)
	}
	defer ring.Close()
	active, err := ring.Active(purpose)
	if err != nil {
		return DataKeyRotation{}, err
	}
	oldIDs, err := decryptOnlyKeyIDs(ctx, database, purpose)
	if err != nil {
		return DataKeyRotation{}, err
	}
	if len(oldIDs) > 0 {
		return DataKeyRotation{Active: active, OldIDs: oldIDs}, nil
	}

	newKey := keyring.DataKey{
		ID: options.NewID(), Purpose: purpose, Status: keyring.StatusActive,
	}
	if newKey.ID == "" {
		return DataKeyRotation{}, fmt.Errorf("data key rotation ID generator returned an empty ID")
	}
	if _, err := io.ReadFull(options.Random, newKey.Material[:]); err != nil {
		return DataKeyRotation{}, fmt.Errorf("generate rotated data key: %w", err)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		wipeDataKeys([]keyring.DataKey{newKey})
		return DataKeyRotation{}, fmt.Errorf("begin data key rotation: %w", err)
	}
	defer tx.Rollback()
	var instanceID, activeMasterID string
	if err := tx.QueryRowContext(ctx, `SELECT id, active_master_key_id FROM instances WHERE singleton = 1`).Scan(&instanceID, &activeMasterID); err != nil {
		wipeDataKeys([]keyring.DataKey{newKey})
		return DataKeyRotation{}, fmt.Errorf("read instance for data key rotation: %w", err)
	}
	if activeMasterID != master.ID {
		wipeDataKeys([]keyring.DataKey{newKey})
		return DataKeyRotation{}, ErrMasterKeyMismatch
	}
	wrapped, err := envelope.Seal(master.Material, newKey.Material[:], dataKeyWrapContext(instanceID, master.ID, newKey.ID), options.Random)
	if err != nil {
		wipeDataKeys([]keyring.DataKey{newKey})
		return DataKeyRotation{}, fmt.Errorf("wrap rotated data key: %w", err)
	}
	now := options.Now.UTC().UnixMilli()
	result, err := tx.ExecContext(ctx, `
UPDATE data_keys SET status = 'decrypt_only'
WHERE id = ? AND purpose = ? AND status = 'active'`, active.ID, string(purpose))
	if err != nil {
		wipeDataKeys([]keyring.DataKey{newKey})
		return DataKeyRotation{}, fmt.Errorf("demote previous data key: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		wipeDataKeys([]keyring.DataKey{newKey})
		return DataKeyRotation{}, fmt.Errorf("previous data key changed during rotation")
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO data_keys(id, purpose, status, created_at)
VALUES (?, ?, 'active', ?)`, newKey.ID, string(purpose), now); err != nil {
		wipeDataKeys([]keyring.DataKey{newKey})
		return DataKeyRotation{}, fmt.Errorf("insert rotated data key: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO master_key_wrappings(
  master_key_id, data_key_id, wrap_version, wrap_nonce,
  wrapped_key, created_at, verified_at
) VALUES (?, ?, ?, ?, ?, ?, ?)`, master.ID, newKey.ID, wrapped.FormatVersion,
		wrapped.Nonce, wrapped.Ciphertext, now, now); err != nil {
		wipeDataKeys([]keyring.DataKey{newKey})
		return DataKeyRotation{}, fmt.Errorf("persist rotated data key wrapping: %w", err)
	}
	if err := tx.Commit(); err != nil {
		wipeDataKeys([]keyring.DataKey{newKey})
		return DataKeyRotation{}, fmt.Errorf("commit data key rotation: %w", err)
	}
	return DataKeyRotation{Active: newKey, OldIDs: []string{active.ID}}, nil
}

func FinalizeBlobDataKeyRotation(ctx context.Context, database *sql.DB, oldIDs []string, now time.Time) error {
	if database == nil || len(oldIDs) == 0 || now.IsZero() {
		return fmt.Errorf("database, old blob key IDs and finalization time are required")
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin blob data key finalization: %w", err)
	}
	defer tx.Rollback()
	for _, id := range oldIDs {
		var references int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM encrypted_blobs WHERE key_id = ?`, id).Scan(&references); err != nil {
			return fmt.Errorf("count blobs using previous data key: %w", err)
		}
		if references != 0 {
			return fmt.Errorf("previous blob data key %s still has %d encrypted blobs", id, references)
		}
		result, err := tx.ExecContext(ctx, `
UPDATE data_keys SET status = 'retired', retired_at = ?
WHERE id = ? AND purpose = ? AND status = 'decrypt_only'`, now.UTC().UnixMilli(), id, string(keyring.PurposeBlob))
		if err != nil {
			return fmt.Errorf("retire previous blob data key: %w", err)
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return fmt.Errorf("previous blob data key is not ready for retirement")
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM master_key_wrappings WHERE data_key_id = ?`, id); err != nil {
			return fmt.Errorf("remove retired blob data key wrapping: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit blob data key finalization: %w", err)
	}
	return nil
}

func decryptOnlyKeyIDs(ctx context.Context, database *sql.DB, purpose keyring.Purpose) ([]string, error) {
	rows, err := database.QueryContext(ctx, `
SELECT id FROM data_keys WHERE purpose = ? AND status = 'decrypt_only' ORDER BY id`, string(purpose))
	if err != nil {
		return nil, fmt.Errorf("list decrypt-only data keys: %w", err)
	}
	defer rows.Close()
	result := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("read decrypt-only data key: %w", err)
		}
		result = append(result, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate decrypt-only data keys: %w", err)
	}
	return result, nil
}

func PrepareMasterKeyRotation(ctx context.Context, database *sql.DB, current, next masterkey.Key, options MasterKeyRotationOptions) error {
	if database == nil || current.ID == "" || next.ID == "" || current.ID == next.ID {
		return fmt.Errorf("current and distinct next master keys are required")
	}
	if options.Now.IsZero() {
		return fmt.Errorf("master key rotation time is required")
	}
	if options.Random == nil {
		return fmt.Errorf("master key rotation random source is required")
	}
	ring, err := LoadKeys(ctx, database, current)
	if err != nil {
		return fmt.Errorf("verify current master key before rotation: %w", err)
	}
	defer ring.Close()
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin master key rotation preparation: %w", err)
	}
	defer tx.Rollback()
	var instanceID, activeMasterKeyID string
	if err := tx.QueryRowContext(ctx, `SELECT id, active_master_key_id FROM instances WHERE singleton = 1`).Scan(&instanceID, &activeMasterKeyID); err != nil {
		return fmt.Errorf("read active master key for rotation: %w", err)
	}
	if activeMasterKeyID != current.ID {
		return ErrMasterKeyMismatch
	}
	var prepared int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM master_key_slots WHERE state = 'prepared'`).Scan(&prepared); err != nil {
		return fmt.Errorf("inspect prepared master key slots: %w", err)
	}
	if prepared != 0 {
		return ErrMasterKeyRotationPending
	}
	canary, err := envelope.Seal(next.Material, []byte(masterKeyCanary), envelope.Context{
		InstanceID: instanceID, RecordType: "master_key_slots",
		RecordID: next.ID, Field: "canary", Version: 1,
	}, options.Random)
	if err != nil {
		return fmt.Errorf("seal prepared master key canary: %w", err)
	}
	now := options.Now.UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO master_key_slots(
  id, state, format_version, canary_nonce, canary_ciphertext, prepared_at
) VALUES (?, 'prepared', ?, ?, ?, ?)`,
		next.ID, canary.FormatVersion, canary.Nonce, canary.Ciphertext, now); err != nil {
		return fmt.Errorf("insert prepared master key slot: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
SELECT id FROM data_keys WHERE status IN ('active', 'decrypt_only') ORDER BY id`)
	if err != nil {
		return fmt.Errorf("list data keys for master key rotation: %w", err)
	}
	keyIDs := make([]string, 0, len(keyring.RequiredPurposes()))
	for rows.Next() {
		var keyID string
		if err := rows.Scan(&keyID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan data key for master key rotation: %w", err)
		}
		keyIDs = append(keyIDs, keyID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate data keys for master key rotation: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close master key rotation data keys: %w", err)
	}
	for _, keyID := range keyIDs {
		key, err := ring.ByID(keyID)
		if err != nil {
			return fmt.Errorf("load data key %s for rewrapping: %w", keyID, err)
		}
		wrapped, err := envelope.Seal(next.Material, key.Material[:], dataKeyWrapContext(instanceID, next.ID, keyID), options.Random)
		if err != nil {
			return fmt.Errorf("rewrap data key %s: %w", keyID, err)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO master_key_wrappings(
  master_key_id, data_key_id, wrap_version, wrap_nonce,
  wrapped_key, created_at, verified_at
) VALUES (?, ?, ?, ?, ?, ?, ?)`, next.ID, keyID, wrapped.FormatVersion,
			wrapped.Nonce, wrapped.Ciphertext, now, now); err != nil {
			return fmt.Errorf("persist rewrapped data key %s: %w", keyID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit master key rotation preparation: %w", err)
	}
	return nil
}

func dataKeyWrapContext(instanceID, masterKeyID, dataKeyID string) envelope.Context {
	return envelope.Context{
		InstanceID: instanceID,
		RecordType: "master_key_wrappings",
		RecordID:   masterKeyID + "/" + dataKeyID,
		Field:      "wrapped_key",
		Version:    1,
	}
}

func wipeDataKeys(keys []keyring.DataKey) {
	for keyIndex := range keys {
		for materialIndex := range keys[keyIndex].Material {
			keys[keyIndex].Material[materialIndex] = 0
		}
	}
}

func appendZeroizableDataKey(keys []keyring.DataKey, key keyring.DataKey) []keyring.DataKey {
	if len(keys) < cap(keys) {
		return append(keys, key)
	}
	capacity := cap(keys) * 2
	if capacity == 0 {
		capacity = 1
	}
	grown := make([]keyring.DataKey, len(keys), capacity)
	copy(grown, keys)
	wipeDataKeys(keys)
	return append(grown, key)
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
