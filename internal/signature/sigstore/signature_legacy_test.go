package sigstore_test

import (
	"encoding/json"
	"errors"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/farcloser/quark/internal/signature/cosign"
	"github.com/farcloser/quark/internal/signature/sigstore"
	"github.com/farcloser/quark/internal/types"
	testcosign "github.com/farcloser/quark/testutil/cosign"
)

// TestConvert_LegacySignature tests converting a legacy cosign signature to sigstore bundle.
func TestLegacySignature_Convert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	// Sign image with legacy format.
	signed, err := testcosign.SignImageLegacy(keyPair)
	assert.NilError(t, err, "SignImageLegacy")

	// Convert to sigstore bundle.
	bundleBytes, mediaType, err := cosign.Convert(signed.Bundle, signed.Annotations)
	assert.NilError(t, err, "Convert")
	assert.Assert(t, len(bundleBytes) > 0, "bundle should not be empty")
	assert.Assert(t, mediaType != "", "mediaType should not be empty")

	// Verify the bundle is valid JSON.
	var bundle map[string]any
	err = json.Unmarshal(bundleBytes, &bundle)
	assert.NilError(t, err, "bundle should be valid JSON")

	// Check bundle has expected structure.
	assert.Assert(t, bundle["mediaType"] != nil, "bundle should have mediaType")
	assert.Assert(t, bundle["verificationMaterial"] != nil, "bundle should have verificationMaterial")
	assert.Assert(t, bundle["messageSignature"] != nil, "bundle should have messageSignature")
}

// TestLegacySignature_VerifyWithKey tests that legacy signatures can be verified.
func TestLegacySignature_VerifyWithKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	// Sign image with legacy format.
	signed, err := testcosign.SignImageLegacy(keyPair)
	assert.NilError(t, err, "SignImageLegacy")

	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Read the signature directly with legacy media type.
	// ReadSignature handles conversion internally and stores the artifact for verification.
	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(signed.Bundle, signed.Annotations, types.MediaType(signed.MediaType))
	assert.NilError(t, err, "ReadSignature")

	// Verify with correct key.
	err = sig.VerifyWithKey(pubKey)
	assert.NilError(t, err, "VerifyWithKey should succeed with correct key")
}

// TestLegacySignature_VerifyWithWrongKey tests that verification fails with wrong key.
func TestLegacySignature_VerifyWithWrongKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	keyPair1, err := testcosign.GenerateKeyPair("test1")
	assert.NilError(t, err, "GenerateKeyPair 1")
	defer keyPair1.Cleanup()

	keyPair2, err := testcosign.GenerateKeyPair("test2")
	assert.NilError(t, err, "GenerateKeyPair 2")
	defer keyPair2.Cleanup()

	// Sign image with legacy format using key pair 1.
	signed, err := testcosign.SignImageLegacy(keyPair1)
	assert.NilError(t, err, "SignImageLegacy")

	wrongPubKey, err := keyPair2.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Read the signature directly with legacy media type.
	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(signed.Bundle, signed.Annotations, types.MediaType(signed.MediaType))
	assert.NilError(t, err, "ReadSignature")

	// Verify with wrong key should fail.
	err = sig.VerifyWithKey(wrongPubKey)
	assert.Assert(t, err != nil, "VerifyWithKey should fail with wrong key")
	assert.Assert(t, errors.Is(err, types.ErrBundleSignatureVerificationFailed),
		"error should wrap ErrBundleSignatureVerificationFailed, got: %v", err)
}

// TestConvert_InvalidPayload tests that Convert rejects invalid payloads.
func TestLegacySignature_InvalidPayload(t *testing.T) {
	t.Parallel()

	annotations := map[string]string{
		testcosign.AnnotationSignature: "c2lnbmF0dXJl", // base64 "signature"
	}

	_, _, err := cosign.Convert([]byte("not json"), annotations)
	assert.Assert(t, err != nil, "Convert should fail with invalid JSON payload")
}

// TestConvert_MissingSignature tests that Convert fails when signature annotation is missing.
func TestLegacySignature_MissingSignature(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"critical":{"identity":{"docker-reference":"test"},"image":{"docker-manifest-digest":"sha256:abc"},"type":"cosign container image signature"},"optional":{}}`)
	annotations := map[string]string{}

	_, _, err := cosign.Convert(payload, annotations)
	assert.Assert(t, err != nil, "Convert should fail with missing signature annotation")
}

// TestConvert_InvalidSignatureBase64 tests that Convert fails with invalid base64 signature.
func TestLegacySignature_InvalidBase64(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"critical":{"identity":{"docker-reference":"test"},"image":{"docker-manifest-digest":"sha256:abc"},"type":"cosign container image signature"},"optional":{}}`)
	annotations := map[string]string{
		testcosign.AnnotationSignature: "not-valid-base64!!!",
	}

	_, _, err := cosign.Convert(payload, annotations)
	assert.Assert(t, err != nil, "Convert should fail with invalid base64 signature")
}

// TestLegacySignature_PreservesAnnotations tests that annotations are preserved through conversion.
func TestLegacySignature_PreservesAnnotations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	// Sign image with legacy format.
	signed, err := testcosign.SignImageLegacy(keyPair)
	assert.NilError(t, err, "SignImageLegacy")

	// Add custom annotation to existing annotations.
	customAnnotations := make(map[string]string)
	for k, v := range signed.Annotations {
		customAnnotations[k] = v
	}
	customAnnotations["custom.annotation/key"] = "custom-value"

	// Read the signature directly with legacy media type and custom annotations.
	// ReadSignature handles conversion internally.
	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(signed.Bundle, customAnnotations, types.MediaType(signed.MediaType))
	assert.NilError(t, err, "ReadSignature")

	// Custom annotations should be preserved (filtered by sigstore).
	resultAnnotations := sig.Annotations()
	assert.Equal(t, resultAnnotations["custom.annotation/key"], "custom-value")
}

// TestReadSignature_LegacyMediaType tests that ReadSignature handles legacy media type.
func TestLegacySignature_ReadWithLegacyMediaType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	// Sign image with legacy format.
	signed, err := testcosign.SignImageLegacy(keyPair)
	assert.NilError(t, err, "SignImageLegacy")

	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// ReadSignature should handle legacy media type directly.
	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(signed.Bundle, signed.Annotations, types.MediaType(signed.MediaType))
	assert.NilError(t, err, "ReadSignature with legacy media type")

	// Verify with correct key.
	err = sig.VerifyWithKey(pubKey)
	assert.NilError(t, err, "VerifyWithKey should succeed")
}
