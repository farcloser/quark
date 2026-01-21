package sigstore_test

import (
	"encoding/json"
	"errors"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/farcloser/quark/internal/types"
	"github.com/farcloser/quark/pkg/sys/signature/cosign"
	"github.com/farcloser/quark/pkg/sys/signature/sigstore"
	testcosign "github.com/farcloser/quark/testutil/cosign"
)

// TestLegacyAttestation_Convert tests converting a legacy DSSE envelope to sigstore bundle.
func TestLegacyAttestation_Convert(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Attest image with legacy format.
	predicate := []byte(`{"test": "data"}`)
	attested, err := testcosign.AttestImageLegacy(keyPair, "custom", predicate)
	assert.NilError(t, err, "AttestImageLegacy")

	// Convert to sigstore bundle.
	bundleBytes, mediaType, err := cosign.ConvertAttestation(attested.Bundle, attested.Annotations)
	assert.NilError(t, err, "ConvertAttestation")
	assert.Assert(t, len(bundleBytes) > 0, "bundle should not be empty")
	assert.Assert(t, mediaType != "", "mediaType should not be empty")

	// Verify the bundle is valid JSON.
	var bundle map[string]any

	err = json.Unmarshal(bundleBytes, &bundle)
	assert.NilError(t, err, "bundle should be valid JSON")

	// Check bundle has expected structure.
	assert.Assert(t, bundle["mediaType"] != nil, "bundle should have mediaType")
	assert.Assert(t, bundle["verificationMaterial"] != nil, "bundle should have verificationMaterial")
	assert.Assert(t, bundle["dsseEnvelope"] != nil, "bundle should have dsseEnvelope")
}

// TestLegacyAttestation_VerifyWithKey tests that legacy attestations can be verified.
func TestLegacyAttestation_VerifyWithKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Attest image with legacy format.
	predicate := []byte(`{"test": "data"}`)
	attested, err := testcosign.AttestImageLegacy(keyPair, "custom", predicate)
	assert.NilError(t, err, "AttestImageLegacy")

	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Read the attestation directly with legacy media type.
	// ReadAttestation handles conversion internally.
	signer := sigstore.NewSigner(nil)
	att, err := signer.ReadAttestation(attested.Bundle, attested.Annotations, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation")

	// Verify with correct key.
	err = att.VerifyWithKey(pubKey)
	assert.NilError(t, err, "VerifyWithKey should succeed with correct key")
}

// TestLegacyAttestation_VerifyWithWrongKey tests that verification fails with wrong key.
func TestLegacyAttestation_VerifyWithWrongKey(t *testing.T) {
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

	// Attest image with legacy format using key pair 1.
	predicate := []byte(`{"test": "data"}`)
	attested, err := testcosign.AttestImageLegacy(keyPair1, "custom", predicate)
	assert.NilError(t, err, "AttestImageLegacy")

	wrongPubKey, err := keyPair2.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Read the attestation directly with legacy media type.
	signer := sigstore.NewSigner(nil)
	att, err := signer.ReadAttestation(attested.Bundle, attested.Annotations, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation")

	// Verify with wrong key should fail.
	err = att.VerifyWithKey(wrongPubKey)
	assert.Assert(t, err != nil, "VerifyWithKey should fail with wrong key")
	assert.Assert(t, errors.Is(err, types.ErrBundleSignatureVerificationFailed),
		"error should wrap ErrBundleSignatureVerificationFailed, got: %v", err)
}

// TestLegacyAttestation_InvalidEnvelope tests that ConvertAttestation rejects invalid envelopes.
func TestLegacyAttestation_InvalidEnvelope(t *testing.T) {
	t.Parallel()

	_, _, err := cosign.ConvertAttestation([]byte("not json"), nil)
	assert.Assert(t, err != nil, "ConvertAttestation should fail with invalid JSON")
}

// TestLegacyAttestation_MissingSignature tests that ConvertAttestation fails when signature is missing.
func TestLegacyAttestation_MissingSignature(t *testing.T) {
	t.Parallel()

	// Valid DSSE envelope structure but no signatures.
	envelope := []byte(`{"payload": "dGVzdA==", "payloadType": "application/vnd.in-toto+json", "signatures": []}`)

	_, _, err := cosign.ConvertAttestation(envelope, nil)
	assert.Assert(t, err != nil, "ConvertAttestation should fail with missing signature")
}

// TestLegacyAttestation_InvalidBase64 tests that ConvertAttestation fails with invalid base64.
func TestLegacyAttestation_InvalidBase64(t *testing.T) {
	t.Parallel()

	envelope := []byte(
		`{"payload": "not-valid-base64!!!", "payloadType": "application/vnd.in-toto+json", "signatures": [{"sig": "dGVzdA=="}]}`,
	)

	_, _, err := cosign.ConvertAttestation(envelope, nil)
	assert.Assert(t, err != nil, "ConvertAttestation should fail with invalid base64 payload")
}

// TestLegacyAttestation_PreservesAnnotations tests that annotations are preserved through conversion.
func TestLegacyAttestation_PreservesAnnotations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Attest image with legacy format.
	predicate := []byte(`{"test": "data"}`)
	attested, err := testcosign.AttestImageLegacy(keyPair, "custom", predicate)
	assert.NilError(t, err, "AttestImageLegacy")

	// Add custom annotation to existing annotations.
	customAnnotations := make(map[string]string)
	for k, v := range attested.Annotations {
		customAnnotations[k] = v
	}

	customAnnotations["custom.annotation/key"] = "custom-value"

	// Read the attestation directly with legacy media type and custom annotations.
	signer := sigstore.NewSigner(nil)
	att, err := signer.ReadAttestation(attested.Bundle, customAnnotations, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation")

	// Custom annotations should be preserved.
	resultAnnotations := att.Annotations()
	assert.Equal(t, resultAnnotations["custom.annotation/key"], "custom-value")
}

// TestLegacyAttestation_ReadWithLegacyMediaType tests that ReadAttestation handles legacy media type.
func TestLegacyAttestation_ReadWithLegacyMediaType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Attest image with legacy format.
	predicate := []byte(`{"test": "data"}`)
	attested, err := testcosign.AttestImageLegacy(keyPair, "custom", predicate)
	assert.NilError(t, err, "AttestImageLegacy")

	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// ReadAttestation should handle legacy media type directly.
	signer := sigstore.NewSigner(nil)
	att, err := signer.ReadAttestation(attested.Bundle, attested.Annotations, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation with legacy media type")

	// Verify with correct key.
	err = att.VerifyWithKey(pubKey)
	assert.NilError(t, err, "VerifyWithKey should succeed")
}

// TestLegacyAttestation_PayloadContainsSubjects tests that subjects are extracted correctly.
func TestLegacyAttestation_PayloadContainsSubjects(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Attest image with legacy format.
	predicate := []byte(`{"test": "data"}`)
	attested, err := testcosign.AttestImageLegacy(keyPair, "custom", predicate)
	assert.NilError(t, err, "AttestImageLegacy")

	// Read the attestation.
	signer := sigstore.NewSigner(nil)
	att, err := signer.ReadAttestation(attested.Bundle, attested.Annotations, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation")

	// Get the statement and check subjects.
	statement := att.Payload()
	assert.Assert(t, len(statement.Subject) > 0, "statement should have subjects")
	assert.Assert(t, len(statement.Subject[0].Digest) > 0, "subject should have digest")
}

// TestLegacyAttestation_PayloadContainsPredicate tests that predicate is extracted correctly.
func TestLegacyAttestation_PayloadContainsPredicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Attest image with legacy format.
	predicate := []byte(`{"test": "data", "nested": {"value": 123}}`)
	attested, err := testcosign.AttestImageLegacy(keyPair, "custom", predicate)
	assert.NilError(t, err, "AttestImageLegacy")

	// Read the attestation.
	signer := sigstore.NewSigner(nil)
	att, err := signer.ReadAttestation(attested.Bundle, attested.Annotations, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation")

	// Get the statement and check predicate.
	statement := att.Payload()
	assert.Assert(t, statement.Predicate != nil, "statement should have predicate")

	// Parse predicate to verify structure (Predicate is stored as json.RawMessage).
	predicateBytes, ok := statement.Predicate.(json.RawMessage)
	assert.Assert(t, ok, "predicate should be json.RawMessage")

	var predicateData map[string]any

	err = json.Unmarshal(predicateBytes, &predicateData)
	assert.NilError(t, err, "unmarshal predicate")

	// Cosign wraps custom predicates in a "Data" field.
	if dataStr, ok := predicateData["Data"].(string); ok {
		var innerData map[string]any

		err = json.Unmarshal([]byte(dataStr), &innerData)
		assert.NilError(t, err, "unmarshal inner data")
		assert.Equal(t, innerData["test"], "data")
	} else {
		// Direct predicate access.
		assert.Equal(t, predicateData["test"], "data")
	}
}
