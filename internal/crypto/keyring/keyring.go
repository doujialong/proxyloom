package keyring

import (
	"errors"
	"fmt"
)

type Purpose string

const (
	PurposeData        Purpose = "data"
	PurposeBlob        Purpose = "blob"
	PurposeFingerprint Purpose = "fingerprint_hmac"
	PurposeHealth      Purpose = "health_hmac"
	PurposeToken       Purpose = "token_hmac"
	PurposeContent     Purpose = "content_hmac"
)

type Status string

const (
	StatusActive      Status = "active"
	StatusDecryptOnly Status = "decrypt_only"
)

var ErrKeyNotFound = errors.New("data key not found")

type DataKey struct {
	ID       string
	Purpose  Purpose
	Status   Status
	Material [32]byte
}

type Ring struct {
	instanceID      string
	keysByID        map[string]DataKey
	activeByPurpose map[Purpose]string
}

func RequiredPurposes() []Purpose {
	return []Purpose{
		PurposeData,
		PurposeBlob,
		PurposeFingerprint,
		PurposeHealth,
		PurposeToken,
		PurposeContent,
	}
}

func New(instanceID string, keys []DataKey) (*Ring, error) {
	if instanceID == "" {
		return nil, fmt.Errorf("instance ID is required")
	}
	ring := &Ring{
		instanceID:      instanceID,
		keysByID:        make(map[string]DataKey, len(keys)),
		activeByPurpose: make(map[Purpose]string),
	}
	fail := func(err error) (*Ring, error) {
		ring.Close()
		return nil, err
	}
	knownPurposes := make(map[Purpose]struct{})
	for _, purpose := range RequiredPurposes() {
		knownPurposes[purpose] = struct{}{}
	}
	for index := range keys {
		key := &keys[index]
		if key.ID == "" {
			return fail(fmt.Errorf("data key ID is required"))
		}
		if _, known := knownPurposes[key.Purpose]; !known {
			return fail(fmt.Errorf("unknown data key purpose %q", key.Purpose))
		}
		if key.Status != StatusActive && key.Status != StatusDecryptOnly {
			return fail(fmt.Errorf("invalid data key status %q", key.Status))
		}
		if _, duplicate := ring.keysByID[key.ID]; duplicate {
			return fail(fmt.Errorf("duplicate data key ID %q", key.ID))
		}
		if key.Status == StatusActive {
			if _, duplicate := ring.activeByPurpose[key.Purpose]; duplicate {
				return fail(fmt.Errorf("multiple active keys for purpose %q", key.Purpose))
			}
			ring.activeByPurpose[key.Purpose] = key.ID
		}
		ring.keysByID[key.ID] = *key
	}
	for _, purpose := range RequiredPurposes() {
		if _, exists := ring.activeByPurpose[purpose]; !exists {
			return fail(fmt.Errorf("missing active key for purpose %q", purpose))
		}
	}
	return ring, nil
}

func (r *Ring) InstanceID() string {
	if r == nil {
		return ""
	}
	return r.instanceID
}

func (r *Ring) Active(purpose Purpose) (DataKey, error) {
	if r == nil {
		return DataKey{}, ErrKeyNotFound
	}
	id, exists := r.activeByPurpose[purpose]
	if !exists {
		return DataKey{}, fmt.Errorf("%w for purpose %q", ErrKeyNotFound, purpose)
	}
	return r.keysByID[id], nil
}

func (r *Ring) ByID(id string) (DataKey, error) {
	if r == nil {
		return DataKey{}, ErrKeyNotFound
	}
	key, exists := r.keysByID[id]
	if !exists {
		return DataKey{}, fmt.Errorf("%w: %s", ErrKeyNotFound, id)
	}
	return key, nil
}

func (r *Ring) Close() {
	if r == nil {
		return
	}
	for id, key := range r.keysByID {
		for index := range key.Material {
			key.Material[index] = 0
		}
		r.keysByID[id] = key
	}
	for id := range r.keysByID {
		delete(r.keysByID, id)
	}
	for purpose := range r.activeByPurpose {
		delete(r.activeByPurpose, purpose)
	}
	r.instanceID = ""
}
