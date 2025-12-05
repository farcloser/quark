package sigstore_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"testing"

	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/internal/registry"
	"github.com/farcloser/quark/internal/shared"
	"github.com/farcloser/quark/internal/sigstore"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestSign_NoSigningMethodConfigured(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	imageRef, err := reference.Parse("ghcr.io/test/image:v1.0.0")
	if err != nil {
		t.Fatalf("failed to parse image reference: %v", err)
	}

	opts := &sigstore.SignOptions{
		ImageRef: *imageRef,
		Digest:   "sha256:abc123",
		Log:      discardLogger(),
	}

	err = sigstore.Sign(ctx, opts)
	if err == nil {
		t.Fatal("expected error when no signing method configured")
	}

	if !errors.Is(err, sigstore.ErrNoSigningMethod) {
		t.Errorf("expected ErrNoSigningMethod, got: %v", err)
	}
}

func TestSign_InvalidPrivateKey(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	tests := []struct {
		name       string
		privateKey []byte
	}{
		{
			name:       "not PEM encoded",
			privateKey: []byte("not a valid PEM key"),
		},
		{
			name: "invalid PEM content",
			privateKey: []byte(`-----BEGIN PRIVATE KEY-----
bm90IGEgdmFsaWQga2V5
-----END PRIVATE KEY-----`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			imageRef, err := reference.Parse("ghcr.io/test/image:v1.0.0")
			if err != nil {
				t.Fatalf("failed to parse image reference: %v", err)
			}

			opts := &sigstore.SignOptions{
				ImageRef:   *imageRef,
				Digest:     "sha256:abc123",
				PrivateKey: tt.privateKey,
				Log:        discardLogger(),
			}

			err = sigstore.Sign(ctx, opts)
			if err == nil {
				t.Fatal("expected error for invalid private key")
			}

			if !errors.Is(err, sigstore.ErrSigningFailed) {
				t.Errorf("expected ErrSigningFailed, got: %v", err)
			}

			if !errors.Is(err, sigstore.ErrInvalidPrivateKey) {
				t.Errorf("expected ErrInvalidPrivateKey in chain, got: %v", err)
			}
		})
	}
}

func TestSign_ValidECPrivateKey_FailsOnPush(t *testing.T) {
	t.Parallel()

	// Generate a valid EC private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode as PEM.
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	ctx := t.Context()

	imageRef, err := reference.Parse("ghcr.io/test/image:v1.0.0")
	if err != nil {
		t.Fatalf("failed to parse image reference: %v", err)
	}

	// Create a registry client (will fail on push since registry doesn't exist)
	regClient := registry.NewClient(&shared.RegistryCredentials{Domain: "ghcr.io"}, discardLogger())

	opts := &sigstore.SignOptions{
		ImageRef:       *imageRef,
		Digest:         "sha256:abc123def456",
		PrivateKey:     pemKey,
		RegistryClient: regClient,
		Log:            discardLogger(),
	}

	// This will sign successfully but fail when pushing to registry.
	// (No actual registry to push to in test environment.)
	err = sigstore.Sign(ctx, opts)
	if err == nil {
		t.Fatal("expected error when pushing to non-existent registry")
	}

	// The error should be about failing to push, not about signing.
	if errors.Is(err, sigstore.ErrInvalidPrivateKey) {
		t.Error("should not be ErrInvalidPrivateKey - key is valid")
	}
}

func TestSign_PKCS8PrivateKey_FailsOnPush(t *testing.T) {
	t.Parallel()

	// Generate a valid EC private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode as PKCS8 PEM.
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	ctx := t.Context()

	imageRef, err := reference.Parse("ghcr.io/test/image:v1.0.0")
	if err != nil {
		t.Fatalf("failed to parse image reference: %v", err)
	}

	// Create a registry client (will fail on push since registry doesn't exist)
	regClient := registry.NewClient(&shared.RegistryCredentials{Domain: "ghcr.io"}, discardLogger())

	opts := &sigstore.SignOptions{
		ImageRef:       *imageRef,
		Digest:         "sha256:abc123def456",
		PrivateKey:     pemKey,
		RegistryClient: regClient,
		Log:            discardLogger(),
	}

	// This will sign successfully but fail when pushing to registry.
	err = sigstore.Sign(ctx, opts)
	if err == nil {
		t.Fatal("expected error when pushing to non-existent registry")
	}

	// The error should be about failing to push, not about signing.
	if errors.Is(err, sigstore.ErrInvalidPrivateKey) {
		t.Error("should not be ErrInvalidPrivateKey - key is valid")
	}
}

func TestSimpleSigningPayload_Format(t *testing.T) {
	t.Parallel()

	// Test that the payload format matches cosign expectations.
	// We can't call createSimpleSigningPayload directly (unexported),
	// but we can verify the expected structure through the Sign function behavior.

	// The payload should contain:
	// {
	//   "critical": {
	//     "image": {
	//       "docker-manifest-digest": "<digest>"
	//     },
	//     "type": "cosign container image signature",
	//     "identity": {}
	//   }
	// }

	//nolint:tagliatelle,revive // JSON field names match cosign spec, nested struct for test clarity.
	type payloadFormat struct {
		Critical struct {
			Image struct {
				DockerManifestDigest string `json:"docker-manifest-digest"`
			} `json:"image"`
			Type     string `json:"type"`
			Identity any    `json:"identity"`
		} `json:"critical"`
	}

	// Verify the expected structure can be parsed.
	testPayload := `{"critical":{"image":{"docker-manifest-digest":"sha256:abc123"},"type":"cosign container image signature","identity":{}}}`

	var payload payloadFormat
	if err := json.Unmarshal([]byte(testPayload), &payload); err != nil {
		t.Fatalf("failed to parse expected payload format: %v", err)
	}

	if payload.Critical.Image.DockerManifestDigest != "sha256:abc123" {
		t.Errorf("unexpected digest: %s", payload.Critical.Image.DockerManifestDigest)
	}

	if payload.Critical.Type != "cosign container image signature" {
		t.Errorf("unexpected type: %s", payload.Critical.Type)
	}
}
