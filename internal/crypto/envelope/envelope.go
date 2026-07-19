package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	FormatVersion = 1
	KeyBytes      = 32
	NonceBytes    = 12
	maxAADField   = 1 << 20
)

var (
	ErrIntegrity = errors.New("crypto integrity failed")
	ErrInvalid   = errors.New("invalid crypto envelope")
)

type Context struct {
	InstanceID string
	RecordType string
	RecordID   string
	Field      string
	Version    uint32
}

type Envelope struct {
	FormatVersion uint32
	Nonce         []byte
	Ciphertext    []byte
}

func Seal(key [KeyBytes]byte, plaintext []byte, context Context, random io.Reader) (Envelope, error) {
	if random == nil {
		return Envelope{}, fmt.Errorf("random source is required")
	}
	aad, err := encodeAAD(context)
	if err != nil {
		return Envelope{}, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, NonceBytes)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate envelope nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return Envelope{
		FormatVersion: FormatVersion,
		Nonce:         nonce,
		Ciphertext:    ciphertext,
	}, nil
}

func Open(key [KeyBytes]byte, input Envelope, context Context) ([]byte, error) {
	if input.FormatVersion != FormatVersion || len(input.Nonce) != NonceBytes || len(input.Ciphertext) < 16 {
		return nil, ErrInvalid
	}
	aad, err := encodeAAD(context)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, input.Nonce, input.Ciphertext, aad)
	if err != nil {
		return nil, ErrIntegrity
	}
	return plaintext, nil
}

func encodeAAD(context Context) ([]byte, error) {
	if context.Version == 0 {
		return nil, fmt.Errorf("%w: AAD version is required", ErrInvalid)
	}
	fields := []string{context.InstanceID, context.RecordType, context.RecordID, context.Field}
	for _, field := range fields {
		if field == "" || len(field) > maxAADField {
			return nil, fmt.Errorf("%w: AAD fields must be non-empty and bounded", ErrInvalid)
		}
	}
	const magic = "proxyloom-aad-v1\x00"
	size := len(magic) + 4
	for _, field := range fields {
		size += 4 + len(field)
	}
	encoded := make([]byte, 0, size)
	encoded = append(encoded, magic...)
	var number [4]byte
	binary.BigEndian.PutUint32(number[:], context.Version)
	encoded = append(encoded, number[:]...)
	for _, field := range fields {
		binary.BigEndian.PutUint32(number[:], uint32(len(field)))
		encoded = append(encoded, number[:]...)
		encoded = append(encoded, field...)
	}
	return encoded, nil
}

func newAEAD(key [KeyBytes]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create AES-256 cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	return aead, nil
}
