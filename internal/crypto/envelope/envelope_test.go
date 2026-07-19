package envelope

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := testKey(0x42)
	context := testContext()
	sealed, err := Seal(key, []byte("fixture secret"), context, bytes.NewReader(bytes.Repeat([]byte{0x11}, NonceBytes)))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if sealed.FormatVersion != FormatVersion || len(sealed.Nonce) != NonceBytes || bytes.Contains(sealed.Ciphertext, []byte("fixture secret")) {
		t.Fatalf("sealed envelope = %+v", sealed)
	}
	plaintext, err := Open(key, sealed, context)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if string(plaintext) != "fixture secret" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestOpenRejectsWrongKeyCiphertextAndAAD(t *testing.T) {
	key := testKey(0x42)
	context := testContext()
	sealed, err := Seal(key, []byte("fixture secret"), context, bytes.NewReader(bytes.Repeat([]byte{0x11}, NonceBytes)))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		key     [KeyBytes]byte
		input   Envelope
		context Context
	}{
		{name: "wrong key", key: testKey(0x43), input: sealed, context: context},
		{name: "instance ID", key: key, input: sealed, context: withInstanceID(context, "other-instance")},
		{name: "record ID", key: key, input: sealed, context: withRecordID(context, "other-record")},
		{name: "record type", key: key, input: sealed, context: withRecordType(context, "other-type")},
		{name: "field", key: key, input: sealed, context: withField(context, "other-field")},
		{name: "AAD version", key: key, input: sealed, context: withVersion(context, 2)},
	}
	corrupted := sealed
	corrupted.Ciphertext = append([]byte(nil), sealed.Ciphertext...)
	corrupted.Ciphertext[0] ^= 0x80
	tests = append(tests, struct {
		name    string
		key     [KeyBytes]byte
		input   Envelope
		context Context
	}{name: "ciphertext", key: key, input: corrupted, context: context})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Open(test.key, test.input, test.context); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("Open() error = %v", err)
			}
		})
	}
}

func TestEnvelopeRejectsInvalidInputs(t *testing.T) {
	key := testKey(0x42)
	if _, err := Seal(key, nil, testContext(), nil); err == nil {
		t.Fatal("Seal() accepted nil random source")
	}
	invalidContext := testContext()
	invalidContext.RecordID = ""
	if _, err := Seal(key, nil, invalidContext, bytes.NewReader(make([]byte, NonceBytes))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Seal() error = %v", err)
	}
	invalidContext = testContext()
	invalidContext.Version = 0
	if _, err := Seal(key, nil, invalidContext, bytes.NewReader(make([]byte, NonceBytes))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Seal() zero AAD version error = %v", err)
	}
	if _, err := Open(key, Envelope{FormatVersion: 99}, testContext()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Open() error = %v", err)
	}
}

func testKey(value byte) [KeyBytes]byte {
	var key [KeyBytes]byte
	for index := range key {
		key[index] = value
	}
	return key
}

func testContext() Context {
	return Context{
		InstanceID: "00000000-0000-7000-8000-000000000001",
		RecordType: "fixture",
		RecordID:   "00000000-0000-7000-8000-000000000002",
		Field:      "secret",
		Version:    1,
	}
}

func withRecordID(context Context, value string) Context {
	context.RecordID = value
	return context
}

func withInstanceID(context Context, value string) Context {
	context.InstanceID = value
	return context
}

func withRecordType(context Context, value string) Context {
	context.RecordType = value
	return context
}

func withField(context Context, value string) Context {
	context.Field = value
	return context
}

func withVersion(context Context, value uint32) Context {
	context.Version = value
	return context
}
