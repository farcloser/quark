package cosign_test

import (
	"strings"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/farcloser/quark/testutil"
	"github.com/farcloser/quark/testutil/cosign"
)

func TestGenerateKeyPair(t *testing.T) {
	t.Parallel()

	kp, err := cosign.GenerateKeyPair("test-password")
	assert.NilError(t, err, "GenerateKeyPair should succeed")

	defer kp.Cleanup()

	pubKey, err := kp.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey should succeed")
	assert.Assert(t, len(pubKey) > 0, "public key should not be empty")
	assert.Assert(t, strings.HasPrefix(string(pubKey), "-----BEGIN PUBLIC KEY-----"), "should be PEM format")
}

func TestSignImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	if !testutil.DockerAvailable(t.Context()) {
		t.Skip("Docker not available")
	}

	t.Parallel()

	kp, err := cosign.GenerateKeyPair("test-password")
	assert.NilError(t, err)

	defer kp.Cleanup()

	signed, err := cosign.SignImage(kp, false)
	assert.NilError(t, err, "SignImage should succeed")
	assert.Assert(t, signed.ImageRef != "", "ImageRef should not be empty")
	assert.Assert(t, signed.Digest != "", "Digest should not be empty")
	assert.Assert(t, len(signed.Bundle) > 0, "Bundle should not be empty")
	assert.Equal(t, signed.MediaType, "application/vnd.dev.sigstore.bundle.v0.3+json")
}

func TestSignImageLegacy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	if !testutil.DockerAvailable(t.Context()) {
		t.Skip("Docker not available")
	}

	t.Parallel()

	kp, err := cosign.GenerateKeyPair("test-password")
	assert.NilError(t, err)

	defer kp.Cleanup()

	signed, err := cosign.SignImageLegacy(kp)
	assert.NilError(t, err, "SignImageLegacy should succeed")
	assert.Assert(t, signed.ImageRef != "", "ImageRef should not be empty")
	assert.Assert(t, signed.Digest != "", "Digest should not be empty")
	assert.Assert(t, len(signed.Bundle) > 0, "Bundle should not be empty")
	assert.Equal(t, signed.MediaType, "application/vnd.dev.cosign.simplesigning.v1+json")

	// Legacy format should have signature in annotations.
	sig, hasSig := signed.Annotations[cosign.AnnotationSignature]
	assert.Assert(t, hasSig, "should have signature annotation")
	assert.Assert(t, len(sig) > 0, "signature should not be empty")
}

func TestAttestImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	if !testutil.DockerAvailable(t.Context()) {
		t.Skip("Docker not available")
	}

	t.Parallel()

	kp, err := cosign.GenerateKeyPair("test-password")
	assert.NilError(t, err)

	defer kp.Cleanup()

	predicate := []byte(`{"customKey": "customValue", "version": "1.0"}`)

	attested, err := cosign.AttestImage(kp, "custom", predicate, false)
	assert.NilError(t, err, "AttestImage should succeed")
	assert.Assert(t, attested.ImageRef != "", "ImageRef should not be empty")
	assert.Assert(t, attested.Digest != "", "Digest should not be empty")
	assert.Assert(t, len(attested.Bundle) > 0, "Bundle should not be empty")
	assert.Equal(t, attested.MediaType, "application/vnd.dev.sigstore.bundle.v0.3+json")
}

func TestAttestImageLegacy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	if !testutil.DockerAvailable(t.Context()) {
		t.Skip("Docker not available")
	}

	t.Parallel()

	kp, err := cosign.GenerateKeyPair("test-password")
	assert.NilError(t, err)

	defer kp.Cleanup()

	predicate := []byte(`{"customKey": "customValue", "version": "1.0"}`)

	attested, err := cosign.AttestImageLegacy(kp, "custom", predicate)
	assert.NilError(t, err, "AttestImageLegacy should succeed")
	assert.Assert(t, attested.ImageRef != "", "ImageRef should not be empty")
	assert.Assert(t, attested.Digest != "", "Digest should not be empty")
	assert.Assert(t, len(attested.Bundle) > 0, "Bundle should not be empty")
	assert.Equal(t, attested.MediaType, "application/vnd.dsse.envelope.v1+json")
}
