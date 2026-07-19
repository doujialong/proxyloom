package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/doujialong/proxyloom/internal/jsonlossless"
)

const Algorithm = "hmac-sha256"

type Kind string

const (
	KindSemantic         Kind = "semantic"
	KindOpaqueStructural Kind = "opaque_structural"
	OpaqueProjection          = "opaque-json-v1"
	OpaqueURIProjection       = "opaque-uri-v1"
)

type Projection struct {
	Node              *jsonlossless.Node
	Kind              Kind
	Version           string
	ExcludeRootMember string
}

type ByteProjection struct {
	Value   []byte
	Kind    Kind
	Version string
}

type Fingerprint struct {
	Kind              Kind
	Algorithm         string
	ProjectionVersion string
	KeyID             string
	Digest            string
}

func (f Fingerprint) MatchKey() string {
	return f.Algorithm + ":" + string(f.Kind) + ":" + f.ProjectionVersion + ":" + f.KeyID + ":" + f.Digest
}

type Fingerprinter struct {
	key   []byte
	keyID string
}

func NewFingerprinter(key []byte, keyID string) (*Fingerprinter, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("fingerprint key must contain exactly 32 bytes")
	}
	if keyID == "" {
		return nil, fmt.Errorf("fingerprint key ID is required")
	}
	return &Fingerprinter{key: append([]byte(nil), key...), keyID: keyID}, nil
}

func (f *Fingerprinter) Sum(input Projection) (Fingerprint, error) {
	if f == nil {
		return Fingerprint{}, fmt.Errorf("fingerprinter is nil")
	}
	if input.Node == nil {
		return Fingerprint{}, fmt.Errorf("fingerprint projection node is required")
	}
	if input.Kind != KindSemantic && input.Kind != KindOpaqueStructural {
		return Fingerprint{}, fmt.Errorf("unsupported fingerprint kind %q", input.Kind)
	}
	if input.Version == "" {
		return Fingerprint{}, fmt.Errorf("fingerprint projection version is required")
	}
	projection, err := jsonlossless.MarshalOpaqueV1(input.Node, input.ExcludeRootMember)
	if err != nil {
		return Fingerprint{}, err
	}
	return f.sum(input.Kind, input.Version, projection), nil
}

func (f *Fingerprinter) SumBytes(input ByteProjection) (Fingerprint, error) {
	if f == nil {
		return Fingerprint{}, fmt.Errorf("fingerprinter is nil")
	}
	if len(input.Value) == 0 {
		return Fingerprint{}, fmt.Errorf("fingerprint byte projection is required")
	}
	if input.Kind != KindSemantic && input.Kind != KindOpaqueStructural {
		return Fingerprint{}, fmt.Errorf("unsupported fingerprint kind %q", input.Kind)
	}
	if input.Version == "" {
		return Fingerprint{}, fmt.Errorf("fingerprint projection version is required")
	}
	return f.sum(input.Kind, input.Version, input.Value), nil
}

func (f *Fingerprinter) sum(kind Kind, version string, projection []byte) Fingerprint {
	mac := hmac.New(sha256.New, f.key)
	mac.Write([]byte("proxyloom-fingerprint-v1\x00"))
	mac.Write([]byte(version))
	mac.Write([]byte{0})
	mac.Write(projection)
	digest := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return Fingerprint{
		Kind:              kind,
		Algorithm:         Algorithm,
		ProjectionVersion: version,
		KeyID:             f.keyID,
		Digest:            digest,
	}
}
