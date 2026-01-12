package types

import (
	"errors"
	"time"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/sigstore-go/pkg/root"
)

type Trusted = root.TrustedRoot
type Statement = in_toto.Statement

type Root interface {
	FromBytes(data []byte) error
	FromNetwork() error
	Get() *Trusted
}

type envelope interface {
	Annotations() map[string]string
	Timestamp() *time.Time
	Verify() (*KeylessSignerInfo, error)
	VerifyWithKey(publicKey []byte) error
}

type Signature interface {
	envelope

	Digests() []Digest
}

type Attestation interface {
	envelope

	// XXX: specialize?
	Payload() *Statement
}

type Signer interface {
	Sign(digest Digest) Signature
	ReadSignature(payload []byte, annotations map[string]string, mediaType MediaType) (Signature, error)
	ReadAttestation(payload []byte, annotations map[string]string, mediaType MediaType) (Attestation, error)
}

// KeylessSignerInfo contains identity from a Fulcio certificate.
type KeylessSignerInfo struct {
	Subject string
	Issuer  string
}

var (
	ErrBundleReadFailed                  = errors.New("failed reading bundle")
	ErrBundleSignatureVerificationFailed = errors.New("signature verification failed")
)
