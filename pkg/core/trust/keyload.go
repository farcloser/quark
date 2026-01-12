package trust

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/farcloser/quark/pkg/fault"
)

const (
	privateKeyPEMType     string = "PRIVATE KEY"
	publicKeyPEMType      string = "PUBLIC KEY"
	pkcs1PublicKeyPEMType string = "RSA PUBLIC KEY"
)

// PEMToPublicKey converts a PEM-encoded byte slice into a crypto.PublicKey.
func PEMToPublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	derBytes, _ := pem.Decode(pemBytes)
	if derBytes == nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrInvalidArgument, ErrPEMDecodeFailed)
	}

	var (
		pub crypto.PublicKey
		err error
	)

	switch derBytes.Type {
	case publicKeyPEMType:
		pub, err = x509.ParsePKIXPublicKey(derBytes.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", fault.ErrInvalidArgument, ErrParsePublicKeyFailed)
		}
	case pkcs1PublicKeyPEMType:
		pub, err = x509.ParsePKCS1PublicKey(derBytes.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", fault.ErrInvalidArgument, ErrParsePublicKeyFailed)
		}
	default:
		return nil, fmt.Errorf("%w: %w: %v",
			fault.ErrNotImplemented,
			ErrUnknownKeyType,
			derBytes.Type)
	}

	return pub, nil
}

// PublicKeyToPEM converts a crypto.PublicKey into a PEM-encoded byte slice.
func PublicKeyToPEM(pub crypto.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrInvalidArgument, ErrEmptyKey)
	}

	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %w: %w", fault.ErrInvalidArgument, ErrFailedToMarshal, err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  publicKeyPEMType,
		Bytes: derBytes,
	}), nil
}
