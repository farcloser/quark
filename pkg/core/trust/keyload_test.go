package trust_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/farcloser/quark/pkg/core/trust"
	"github.com/farcloser/quark/pkg/fault"
)

func TestPEMToPublicKey_ValidPKIX_EC(t *testing.T) {
	t.Parallel()

	// Generate an EC key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	// Marshal public key to PKIX format
	derBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	pub, err := trust.PEMToPublicKey(pemBytes)
	if err != nil {
		t.Fatalf("PEMToPublicKey failed: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}

	if !ecPub.Equal(&privateKey.PublicKey) {
		t.Error("parsed key does not match original")
	}
}

func TestPEMToPublicKey_ValidPKIX_RSA(t *testing.T) {
	t.Parallel()

	// Generate an RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Marshal public key to PKIX format
	derBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	pub, err := trust.PEMToPublicKey(pemBytes)
	if err != nil {
		t.Fatalf("PEMToPublicKey failed: %v", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}

	if !rsaPub.Equal(&privateKey.PublicKey) {
		t.Error("parsed key does not match original")
	}
}

func TestPEMToPublicKey_ValidPKCS1_RSA(t *testing.T) {
	t.Parallel()

	// Generate an RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Marshal public key to PKCS1 format
	derBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derBytes,
	})

	pub, err := trust.PEMToPublicKey(pemBytes)
	if err != nil {
		t.Fatalf("PEMToPublicKey failed: %v", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}

	if !rsaPub.Equal(&privateKey.PublicKey) {
		t.Error("parsed key does not match original")
	}
}

func TestPEMToPublicKey_InvalidPEM(t *testing.T) {
	t.Parallel()

	invalidInputs := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"garbage", []byte("not a PEM at all")},
		{"truncated", []byte("-----BEGIN PUBLIC KEY-----\n")},
	}

	for _, tc := range invalidInputs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := trust.PEMToPublicKey(tc.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !errors.Is(err, fault.ErrInvalidArgument) {
				t.Errorf("expected fault.ErrInvalidArgument, got %v", err)
			}

			if !errors.Is(err, trust.ErrPEMDecodeFailed) {
				t.Errorf("expected trust.ErrPEMDecodeFailed, got %v", err)
			}
		})
	}
}

func TestPEMToPublicKey_UnknownPEMType(t *testing.T) {
	t.Parallel()

	// Valid PEM but with unknown type
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "UNKNOWN KEY TYPE",
		Bytes: []byte("some data"),
	})

	_, err := trust.PEMToPublicKey(pemBytes)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, fault.ErrNotImplemented) {
		t.Errorf("expected fault.ErrNotImplemented, got %v", err)
	}

	if !errors.Is(err, trust.ErrUnknownKeyType) {
		t.Errorf("expected trust.ErrUnknownKeyType, got %v", err)
	}
}

func TestPEMToPublicKey_InvalidKeyBytes_PKIX(t *testing.T) {
	t.Parallel()

	// Valid PEM structure but garbage key bytes
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("not valid DER data"),
	})

	_, err := trust.PEMToPublicKey(pemBytes)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("expected fault.ErrInvalidArgument, got %v", err)
	}

	if !errors.Is(err, trust.ErrParsePublicKeyFailed) {
		t.Errorf("expected trust.ErrParsePublicKeyFailed, got %v", err)
	}
}

func TestPEMToPublicKey_InvalidKeyBytes_PKCS1(t *testing.T) {
	t.Parallel()

	// Valid PEM structure but garbage key bytes
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: []byte("not valid DER data"),
	})

	_, err := trust.PEMToPublicKey(pemBytes)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("expected fault.ErrInvalidArgument, got %v", err)
	}

	if !errors.Is(err, trust.ErrParsePublicKeyFailed) {
		t.Errorf("expected trust.ErrParsePublicKeyFailed, got %v", err)
	}
}

func TestPublicKeyToPEM_ValidEC(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	pemBytes, err := trust.PublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToPEM failed: %v", err)
	}

	// Verify the PEM is valid by decoding it
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("failed to decode PEM output")
	}

	if block.Type != "PUBLIC KEY" {
		t.Errorf("expected PEM type 'PUBLIC KEY', got %q", block.Type)
	}

	// Verify we can parse it back
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}

	if !ecPub.Equal(&privateKey.PublicKey) {
		t.Error("round-trip key does not match original")
	}
}

func TestPublicKeyToPEM_ValidRSA(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	pemBytes, err := trust.PublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToPEM failed: %v", err)
	}

	// Verify the PEM is valid by decoding it
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("failed to decode PEM output")
	}

	if block.Type != "PUBLIC KEY" {
		t.Errorf("expected PEM type 'PUBLIC KEY', got %q", block.Type)
	}

	// Verify we can parse it back
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}

	if !rsaPub.Equal(&privateKey.PublicKey) {
		t.Error("round-trip key does not match original")
	}
}

func TestPublicKeyToPEM_NilKey(t *testing.T) {
	t.Parallel()

	_, err := trust.PublicKeyToPEM(nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("expected fault.ErrInvalidArgument, got %v", err)
	}

	if !errors.Is(err, trust.ErrEmptyKey) {
		t.Errorf("expected trust.ErrEmptyKey, got %v", err)
	}
}

func TestPEMToPublicKey_RoundTrip(t *testing.T) {
	t.Parallel()

	// Generate key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	// Convert to PEM
	pemBytes, err := trust.PublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToPEM failed: %v", err)
	}

	// Convert back from PEM
	pub, err := trust.PEMToPublicKey(pemBytes)
	if err != nil {
		t.Fatalf("PEMToPublicKey failed: %v", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}

	if !ecPub.Equal(&privateKey.PublicKey) {
		t.Error("round-trip key does not match original")
	}
}
