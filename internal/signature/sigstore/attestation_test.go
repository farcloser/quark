package sigstore_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/farcloser/quark/internal/signature/sigstore"
	"github.com/farcloser/quark/internal/types"
	testcosign "github.com/farcloser/quark/testutil/cosign"
)

// TestReadAttestation_CosignGeneratedBundle tests ReadAttestation with a real cosign-generated attestation.
func TestAttestation_ReadBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	// Create an attestation with custom predicate.
	predicate := []byte(`{"buildType": "test", "builder": {"id": "test-builder"}}`)
	attested, err := testcosign.AttestImage(keyPair, "custom", predicate, false)
	assert.NilError(t, err, "AttestImage")

	// Create signer without trusted root.
	signer := sigstore.NewSigner(nil)

	// Read the attestation.
	attestation, err := signer.ReadAttestation(attested.Bundle, nil, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation")
	assert.Assert(t, attestation != nil, "attestation should not be nil")

	// Verify the payload contains the statement.
	payload := attestation.Payload()
	assert.Assert(t, payload != nil, "payload should not be nil")
	assert.Assert(t, payload.PredicateType != "", "predicate type should not be empty")
}

// TestReadAttestation_VerifyWithKey tests attestation verification with the signing key.
func TestAttestation_VerifyWithKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	// Create an attestation.
	predicate := []byte(`{"custom": "data"}`)
	attested, err := testcosign.AttestImage(keyPair, "custom", predicate, false)
	assert.NilError(t, err, "AttestImage")

	// Read public key.
	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Read the attestation.
	signer := sigstore.NewSigner(nil)
	attestation, err := signer.ReadAttestation(attested.Bundle, nil, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation")

	// Verify with correct key.
	err = attestation.VerifyWithKey(pubKey)
	assert.NilError(t, err, "VerifyWithKey should succeed with correct key")
}

// TestReadAttestation_VerifyWithWrongKey tests attestation verification with wrong key fails.
func TestAttestation_VerifyWithWrongKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate two key pairs.
	keyPair1, err := testcosign.GenerateKeyPair("test1")
	assert.NilError(t, err, "GenerateKeyPair 1")

	defer keyPair1.Cleanup()

	keyPair2, err := testcosign.GenerateKeyPair("test2")
	assert.NilError(t, err, "GenerateKeyPair 2")

	defer keyPair2.Cleanup()

	// Create attestation with key pair 1.
	predicate := []byte(`{"custom": "data"}`)
	attested, err := testcosign.AttestImage(keyPair1, "custom", predicate, false)
	assert.NilError(t, err, "AttestImage")

	// Read public key from key pair 2.
	wrongPubKey, err := keyPair2.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Read the attestation.
	signer := sigstore.NewSigner(nil)
	attestation, err := signer.ReadAttestation(attested.Bundle, nil, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation")

	// Verify with wrong key should fail.
	err = attestation.VerifyWithKey(wrongPubKey)
	assert.Assert(t, err != nil, "VerifyWithKey should fail with wrong key")
	assert.Assert(t, errors.Is(err, types.ErrBundleSignatureVerificationFailed),
		"error should wrap ErrBundleSignatureVerificationFailed, got: %v", err)
}

// TestReadAttestation_RejectsSignaturePredicateType tests that ReadAttestation rejects signature bundles.
func TestAttestation_RejectsSignatureType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	// Sign an image (creates a signature, not an attestation).
	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	// ReadAttestation should reject signature predicate types.
	signer := sigstore.NewSigner(nil)
	_, err = signer.ReadAttestation(signedImage.Bundle, nil, types.MediaType(signedImage.MediaType))
	assert.Assert(t, err != nil, "ReadAttestation should reject signature predicate type")
	assert.Assert(t, errors.Is(err, types.ErrBundleReadFailed),
		"error should wrap ErrBundleReadFailed, got: %v", err)
}

// TestReadAttestation_PayloadContainsSubjects tests that the payload contains subject digests.
func TestAttestation_PayloadContainsSubjects(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	// Create an attestation.
	predicate := []byte(`{"verified": true}`)
	attested, err := testcosign.AttestImage(keyPair, "custom", predicate, false)
	assert.NilError(t, err, "AttestImage")

	// Read the attestation.
	signer := sigstore.NewSigner(nil)
	attestation, err := signer.ReadAttestation(attested.Bundle, nil, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation")

	// Payload should contain subjects.
	payload := attestation.Payload()
	assert.Assert(t, len(payload.Subject) > 0, "payload should have at least one subject")

	// Subject should have a digest.
	subject := payload.Subject[0]
	assert.Assert(t, len(subject.Digest) > 0, "subject should have at least one digest")
}

// TestReadAttestation_PayloadContainsPredicate tests that the payload contains the custom predicate.
func TestAttestation_PayloadContainsPredicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	// Create an attestation with specific predicate data.
	predicate := []byte(`{"buildInfo": {"version": "1.0.0"}, "materials": []}`)
	attested, err := testcosign.AttestImage(keyPair, "custom", predicate, false)
	assert.NilError(t, err, "AttestImage")

	// Read the attestation.
	signer := sigstore.NewSigner(nil)
	attestation, err := signer.ReadAttestation(attested.Bundle, nil, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation")

	// Payload should contain the predicate.
	payload := attestation.Payload()
	assert.Assert(t, payload.Predicate != nil, "payload should have a predicate")

	// Verify predicate contains expected data (Predicate is stored as json.RawMessage).
	predicateBytes, ok := payload.Predicate.(json.RawMessage)
	assert.Assert(t, ok, "predicate should be json.RawMessage")

	var predicateData map[string]any
	err = json.Unmarshal(predicateBytes, &predicateData)
	assert.NilError(t, err, "unmarshal predicate")

	// When using --type custom, cosign wraps the predicate in a CosignPredicate
	// structure with a Data field containing the original predicate as a JSON string.
	dataStr, hasData := predicateData["Data"].(string)
	if hasData {
		var innerData map[string]any
		err = json.Unmarshal([]byte(dataStr), &innerData)
		assert.NilError(t, err, "unmarshal inner predicate data")
		assert.Assert(t, innerData["buildInfo"] != nil, "predicate.Data should contain buildInfo")
	} else {
		assert.Assert(t, predicateData["buildInfo"] != nil, "predicate should contain buildInfo")
	}
}

// TestReadAttestation_Annotations tests that annotations are preserved.
func TestAttestation_Annotations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	// Create an attestation.
	predicate := []byte(`{}`)
	attested, err := testcosign.AttestImage(keyPair, "custom", predicate, false)
	assert.NilError(t, err, "AttestImage")

	// Read attestation with custom annotations.
	annotations := map[string]string{
		"custom.annotation/key": "value",
	}

	signer := sigstore.NewSigner(nil)
	attestation, err := signer.ReadAttestation(attested.Bundle, annotations, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation")

	// Annotations should be preserved.
	resultAnnotations := attestation.Annotations()
	assert.Equal(t, resultAnnotations["custom.annotation/key"], "value")
}

// =============================================================================
// Tampering Tests - verify that modified attestation bundles are rejected
// =============================================================================

// tamperAttestationPredicate modifies the predicate in an attestation bundle.
func tamperAttestationPredicate(bundle []byte) ([]byte, error) {
	var b map[string]any
	if err := json.Unmarshal(bundle, &b); err != nil {
		return nil, err
	}

	envelope, ok := b["dsseEnvelope"].(map[string]any)
	if !ok {
		return nil, errors.New("no dsseEnvelope")
	}

	payloadB64, ok := envelope["payload"].(string)
	if !ok {
		return nil, errors.New("no payload")
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, err
	}

	var statement map[string]any
	if err := json.Unmarshal(payloadBytes, &statement); err != nil {
		return nil, err
	}

	// Tamper with the predicate.
	statement["predicate"] = map[string]any{"tampered": true, "evil": "data"}

	modifiedPayload, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}

	envelope["payload"] = base64.StdEncoding.EncodeToString(modifiedPayload)

	return json.Marshal(b)
}

// TestVerifyAttestation_TamperedPredicate tests that a tampered predicate is rejected.
func TestAttestation_TamperedPredicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	// Create an attestation.
	predicate := []byte(`{"original": "data"}`)
	attested, err := testcosign.AttestImage(keyPair, "custom", predicate, false)
	assert.NilError(t, err, "AttestImage")

	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Tamper with the predicate.
	tamperedBundle, err := tamperAttestationPredicate(attested.Bundle)
	assert.NilError(t, err, "tamperAttestationPredicate")

	// Read the tampered attestation.
	signer := sigstore.NewSigner(nil)
	attestation, err := signer.ReadAttestation(tamperedBundle, nil, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation should succeed (tampering not detected at parse time)")

	// Verification should fail - signature doesn't match tampered payload.
	err = attestation.VerifyWithKey(pubKey)
	assert.Assert(t, err != nil, "VerifyWithKey should fail with tampered predicate")
	assert.Assert(t, errors.Is(err, types.ErrBundleSignatureVerificationFailed),
		"error should wrap ErrBundleSignatureVerificationFailed, got: %v", err)
}

// tamperAttestationSubject modifies the subject digest in an attestation bundle.
func tamperAttestationSubject(bundle []byte) ([]byte, error) {
	var b map[string]any
	if err := json.Unmarshal(bundle, &b); err != nil {
		return nil, err
	}

	envelope, ok := b["dsseEnvelope"].(map[string]any)
	if !ok {
		return nil, errors.New("no dsseEnvelope")
	}

	payloadB64, ok := envelope["payload"].(string)
	if !ok {
		return nil, errors.New("no payload")
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, err
	}

	var statement map[string]any
	if err := json.Unmarshal(payloadBytes, &statement); err != nil {
		return nil, err
	}

	// Tamper with the subject digest.
	subjects, ok := statement["subject"].([]any)
	if !ok || len(subjects) == 0 {
		return nil, errors.New("no subjects")
	}

	subject, ok := subjects[0].(map[string]any)
	if !ok {
		return nil, errors.New("invalid subject")
	}

	// Replace the digest with a different value.
	subject["digest"] = map[string]string{
		"sha256": "0000000000000000000000000000000000000000000000000000000000000000",
	}

	modifiedPayload, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}

	envelope["payload"] = base64.StdEncoding.EncodeToString(modifiedPayload)

	return json.Marshal(b)
}

// TestVerifyAttestation_TamperedSubject tests that a tampered subject digest is rejected.
func TestAttestation_TamperedSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	// Create an attestation.
	predicate := []byte(`{}`)
	attested, err := testcosign.AttestImage(keyPair, "custom", predicate, false)
	assert.NilError(t, err, "AttestImage")

	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Tamper with the subject.
	tamperedBundle, err := tamperAttestationSubject(attested.Bundle)
	assert.NilError(t, err, "tamperAttestationSubject")

	// Read the tampered attestation.
	signer := sigstore.NewSigner(nil)
	attestation, err := signer.ReadAttestation(tamperedBundle, nil, types.MediaType(attested.MediaType))
	assert.NilError(t, err, "ReadAttestation should succeed (tampering not detected at parse time)")

	// Verification should fail - signature doesn't match tampered payload.
	err = attestation.VerifyWithKey(pubKey)
	assert.Assert(t, err != nil, "VerifyWithKey should fail with tampered subject")
	assert.Assert(t, errors.Is(err, types.ErrBundleSignatureVerificationFailed),
		"error should wrap ErrBundleSignatureVerificationFailed, got: %v", err)
}

// TestReadAttestation_InvalidMediaType tests ReadAttestation with invalid media type.
func TestAttestation_InvalidMediaType(t *testing.T) {
	t.Parallel()

	signer := sigstore.NewSigner(nil)

	_, err := signer.ReadAttestation([]byte(`{}`), nil, types.MediaType("application/json"))
	assert.Assert(t, err != nil, "ReadAttestation should fail with invalid media type")
	assert.Assert(t, errors.Is(err, types.ErrBundleReadFailed),
		"error should wrap ErrBundleReadFailed, got: %v", err)
}

// TestReadAttestation_InvalidJSON tests ReadAttestation with invalid JSON.
func TestAttestation_InvalidJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate a valid attestation to get the expected media type.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")
	defer keyPair.Cleanup()

	predicate := []byte(`{}`)
	attested, err := testcosign.AttestImage(keyPair, "custom", predicate, false)
	assert.NilError(t, err, "AttestImage")

	signer := sigstore.NewSigner(nil)

	// Use the media type from cosign with invalid JSON.
	_, err = signer.ReadAttestation([]byte(`not json`), nil, types.MediaType(attested.MediaType))
	assert.Assert(t, err != nil, "ReadAttestation should fail with invalid JSON")
	assert.Assert(t, errors.Is(err, types.ErrBundleReadFailed),
		"error should wrap ErrBundleReadFailed, got: %v", err)
}
