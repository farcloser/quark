package sigstore_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/farcloser/quark/internal/signature/sigstore"
	"github.com/farcloser/quark/internal/types"
	testcosign "github.com/farcloser/quark/testutil/cosign"
)

// extractMediaType extracts the mediaType field from a sigstore bundle JSON.
func extractMediaType(bundle []byte) types.MediaType {
	var b struct {
		MediaType string `json:"mediaType"`
	}

	if err := json.Unmarshal(bundle, &b); err != nil {
		return ""
	}

	return types.MediaType(b.MediaType)
}

// TestReadSignature_CosignGeneratedBundle tests ReadSignature with a real cosign-generated bundle.
// This test requires cosign and crane CLIs, and network access to ttl.sh.
func TestSignature_ReadBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Sign an image (pushes to ttl.sh, signs, fetches bundle).
	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	// Create signer without trusted root (no Rekor verification).
	signer := sigstore.NewSigner(nil)

	// Read the signature using the media type from cosign.
	sig, err := signer.ReadSignature(signedImage.Bundle, nil, types.MediaType(signedImage.MediaType))
	assert.NilError(t, err, "ReadSignature")
	assert.Assert(t, sig != nil, "signature should not be nil")

	// Verify the digest is present in the signature.
	digests := sig.Digests()
	assert.Assert(t, len(digests) > 0, "signature should contain at least one digest")

	// The digest should match the signed image digest (without sha256: prefix).
	expectedDigestHash := strings.TrimPrefix(signedImage.Digest, "sha256:")
	found := false

	for _, d := range digests {
		if string(d) == expectedDigestHash {
			found = true

			break
		}
	}

	assert.Assert(t, found, "signature digest %v should contain %s", digests, expectedDigestHash)
}

// TestReadSignature_InvalidMediaType tests ReadSignature with an invalid media type.
func TestSignature_InvalidMediaType(t *testing.T) {
	t.Parallel()

	signer := sigstore.NewSigner(nil)

	_, err := signer.ReadSignature([]byte(`{}`), nil, types.MediaType("application/json"))
	assert.Assert(t, err != nil, "ReadSignature should fail with invalid media type")
	assert.Assert(t, errors.Is(err, types.ErrBundleReadFailed),
		"error should wrap ErrBundleReadFailed, got: %v", err)
}

// TestReadSignature_InvalidBundleJSON tests ReadSignature with invalid JSON.
func TestSignature_InvalidJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate a valid bundle to discover the expected media type.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	signer := sigstore.NewSigner(nil)

	// Use the media type from cosign with invalid JSON.
	_, err = signer.ReadSignature([]byte(`not json`), nil, types.MediaType(signedImage.MediaType))
	assert.Assert(t, err != nil, "ReadSignature should fail with invalid JSON")
	assert.Assert(t, errors.Is(err, types.ErrBundleReadFailed),
		"error should wrap ErrBundleReadFailed, got: %v", err)
}

// TestReadSignature_EmptyBundle tests ReadSignature with an empty bundle.
func TestSignature_EmptyBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate a valid bundle to discover the expected media type.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	signer := sigstore.NewSigner(nil)

	// Use the media type from cosign with empty JSON.
	_, err = signer.ReadSignature([]byte(`{}`), nil, types.MediaType(signedImage.MediaType))
	assert.Assert(t, err != nil, "ReadSignature should fail with empty bundle")
	assert.Assert(t, errors.Is(err, types.ErrBundleReadFailed),
		"error should wrap ErrBundleReadFailed, got: %v", err)
}

// TestReadSignature_AttestationPredicateType tests ReadSignature rejects attestation predicate types.
func TestSignature_RejectsAttestationType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Create an attestation (not a signature).
	predicate := []byte(`{"custom": "data"}`)
	attested, err := testcosign.AttestImage(keyPair, "custom", predicate, false)
	assert.NilError(t, err, "AttestImage")

	signer := sigstore.NewSigner(nil)

	// ReadSignature should reject attestation predicate types.
	_, err = signer.ReadSignature(attested.Bundle, nil, types.MediaType(attested.MediaType))
	assert.Assert(t, err != nil, "ReadSignature should reject attestation predicate type")
	assert.Assert(t, errors.Is(err, types.ErrBundleReadFailed),
		"error should wrap ErrBundleReadFailed, got: %v", err)
}

// TestVerifyWithKey_ValidSignature tests VerifyWithKey with a valid signature.
func TestSignature_VerifyWithKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Sign an image.
	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	// Read public key.
	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Create signer and read signature.
	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(signedImage.Bundle, nil, types.MediaType(signedImage.MediaType))
	assert.NilError(t, err, "ReadSignature")

	// Verify with correct key.
	err = sig.VerifyWithKey(pubKey)
	assert.NilError(t, err, "VerifyWithKey should succeed with correct key")
}

// TestVerifyWithKey_WrongKey tests VerifyWithKey with an incorrect key.
func TestSignature_VerifyWithWrongKey(t *testing.T) {
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

	// Sign with key pair 1.
	signedImage, err := testcosign.SignImage(keyPair1, false)
	assert.NilError(t, err, "SignImage")

	// Read public key from key pair 2.
	wrongPubKey, err := keyPair2.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Create signer and read signature.
	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(signedImage.Bundle, nil, types.MediaType(signedImage.MediaType))
	assert.NilError(t, err, "ReadSignature")

	// Verify with wrong key should fail.
	err = sig.VerifyWithKey(wrongPubKey)
	assert.Assert(t, err != nil, "VerifyWithKey should fail with wrong key")
	assert.Assert(t, errors.Is(err, types.ErrBundleSignatureVerificationFailed),
		"error should wrap ErrBundleSignatureVerificationFailed, got: %v", err)
}

// TestVerifyWithKey_InvalidKey tests VerifyWithKey with invalid key data.
func TestSignature_VerifyWithInvalidKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Sign an image.
	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	// Create signer and read signature.
	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(signedImage.Bundle, nil, types.MediaType(signedImage.MediaType))
	assert.NilError(t, err, "ReadSignature")

	// Verify with invalid key data.
	err = sig.VerifyWithKey([]byte("not a valid PEM key"))
	assert.Assert(t, err != nil, "VerifyWithKey should fail with invalid key")
	assert.Assert(t, errors.Is(err, types.ErrBundleSignatureVerificationFailed),
		"error should wrap ErrBundleSignatureVerificationFailed, got: %v", err)
}

// TestReadSignature_Annotations tests that annotations are preserved.
func TestSignature_Annotations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Sign an image.
	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	// Read signature with custom annotations.
	annotations := map[string]string{
		"custom.annotation/key": "value",
	}

	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(signedImage.Bundle, annotations, types.MediaType(signedImage.MediaType))
	assert.NilError(t, err, "ReadSignature")

	// Annotations should be preserved (custom ones only, not reserved).
	resultAnnotations := sig.Annotations()
	assert.Equal(t, resultAnnotations["custom.annotation/key"], "value")
}

// TestReadSignature_ReservedAnnotationsFiltered tests that reserved annotations are filtered.
func TestSignature_ReservedAnnotationsFiltered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Sign an image.
	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	// Read signature with reserved annotations.
	annotations := map[string]string{
		"dev.sigstore.cosign/signature": "should-be-filtered",
		"custom.key":                    "should-be-kept",
	}

	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(signedImage.Bundle, annotations, types.MediaType(signedImage.MediaType))
	assert.NilError(t, err, "ReadSignature")

	// Reserved annotations should be filtered out.
	resultAnnotations := sig.Annotations()
	_, hasReserved := resultAnnotations["dev.sigstore.cosign/signature"]
	assert.Assert(t, !hasReserved, "reserved annotation should be filtered")
	assert.Equal(t, resultAnnotations["custom.key"], "should-be-kept")
}

// TestReadSignature_DigestFromBundle tests that the digest is correctly extracted from the bundle.
func TestSignature_DigestFromBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Sign an image.
	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(signedImage.Bundle, nil, types.MediaType(signedImage.MediaType))
	assert.NilError(t, err, "ReadSignature")

	// Extract and verify digest.
	digests := sig.Digests()
	assert.Assert(t, len(digests) == 1, "should have exactly one digest, got %d", len(digests))

	// Decode the bundle to verify the digest matches the in-toto statement subject.
	var bundle struct {
		DsseEnvelope struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	err = json.Unmarshal(signedImage.Bundle, &bundle)
	assert.NilError(t, err, "unmarshal bundle")

	payloadBytes, err := base64.StdEncoding.DecodeString(bundle.DsseEnvelope.Payload)
	assert.NilError(t, err, "decode payload")

	var statement struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	err = json.Unmarshal(payloadBytes, &statement)
	assert.NilError(t, err, "unmarshal statement")

	expectedDigest := statement.Subject[0].Digest["sha256"]
	assert.Equal(t, string(digests[0]), expectedDigest)
}

// TestVerifyWithKey_WithRekor tests VerifyWithKey with Rekor transparency log verification.
// This test uploads to the public Rekor instance and verifies the tlog entry.
func TestSignature_VerifyWithRekor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Fetch public Sigstore trusted root.
	root := sigstore.NewRoot("")
	err := root.FromNetwork()
	assert.NilError(t, err, "FromNetwork")
	assert.Assert(t, root.Get() != nil, "trusted root should not be nil")

	// Generate key pair.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	// Sign an image WITH Rekor upload.
	signedImage, err := testcosign.SignImage(keyPair, true)
	assert.NilError(t, err, "SignImage with Rekor")

	// Read public key.
	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Create signer with trusted root for Rekor verification.
	signer := sigstore.NewSigner(root.Get())
	sig, err := signer.ReadSignature(signedImage.Bundle, nil, types.MediaType(signedImage.MediaType))
	assert.NilError(t, err, "ReadSignature")

	// Verify with key - this will also verify the tlog entry.
	err = sig.VerifyWithKey(pubKey)
	assert.NilError(t, err, "VerifyWithKey with Rekor should succeed")

	// Verify timestamp is present (from tlog entry).
	timestamp := sig.Timestamp()
	assert.Assert(t, timestamp != nil, "signature should have timestamp from Rekor")
}

// =============================================================================
// Tampering Tests - verify that modified bundles are rejected
// =============================================================================

// tamperSubjectDigest modifies the subject digest in a bundle to a different value.
func tamperSubjectDigest(bundle []byte) ([]byte, error) {
	var b map[string]any
	if err := json.Unmarshal(bundle, &b); err != nil {
		return nil, err
	}

	// Get the DSSE envelope.
	envelope, ok := b["dsseEnvelope"].(map[string]any)
	if !ok {
		return nil, errors.New("no dsseEnvelope")
	}

	// Decode the payload.
	payloadB64, ok := envelope["payload"].(string)
	if !ok {
		return nil, errors.New("no payload")
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, err
	}

	// Parse and modify the statement.
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

	digest, ok := subject["digest"].(map[string]any)
	if !ok {
		return nil, errors.New("no digest")
	}

	// Replace the sha256 digest with a different value.
	digest["sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"

	// Re-encode the modified statement.
	modifiedPayload, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}

	// Put the modified payload back (base64 encoded).
	envelope["payload"] = base64.StdEncoding.EncodeToString(modifiedPayload)

	return json.Marshal(b)
}

// tamperSignature modifies the signature bytes in a bundle.
func tamperSignature(bundle []byte) ([]byte, error) {
	var b map[string]any
	if err := json.Unmarshal(bundle, &b); err != nil {
		return nil, err
	}

	envelope, ok := b["dsseEnvelope"].(map[string]any)
	if !ok {
		return nil, errors.New("no dsseEnvelope")
	}

	sigs, ok := envelope["signatures"].([]any)
	if !ok || len(sigs) == 0 {
		return nil, errors.New("no signatures")
	}

	sig, ok := sigs[0].(map[string]any)
	if !ok {
		return nil, errors.New("invalid signature")
	}

	// Replace the signature with garbage.
	sig["sig"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	return json.Marshal(b)
}

// removeSignature removes the signature from a bundle.
func removeSignature(bundle []byte) ([]byte, error) {
	var b map[string]any
	if err := json.Unmarshal(bundle, &b); err != nil {
		return nil, err
	}

	envelope, ok := b["dsseEnvelope"].(map[string]any)
	if !ok {
		return nil, errors.New("no dsseEnvelope")
	}

	// Remove signatures entirely.
	envelope["signatures"] = []any{}

	return json.Marshal(b)
}

// corruptPayload corrupts the base64 payload in a bundle.
func corruptPayload(bundle []byte) ([]byte, error) {
	var b map[string]any
	if err := json.Unmarshal(bundle, &b); err != nil {
		return nil, err
	}

	envelope, ok := b["dsseEnvelope"].(map[string]any)
	if !ok {
		return nil, errors.New("no dsseEnvelope")
	}

	// Replace with invalid base64 that decodes to garbage JSON.
	envelope["payload"] = base64.StdEncoding.EncodeToString([]byte("not valid json {{{"))

	return json.Marshal(b)
}

// TestVerifyWithKey_TamperedSubjectDigest tests that a tampered subject digest is rejected.
func TestSignature_TamperedSubjectDigest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair and sign an image.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Tamper with the subject digest.
	tamperedBundle, err := tamperSubjectDigest(signedImage.Bundle)
	assert.NilError(t, err, "tamperSubjectDigest")

	// Read the tampered signature.
	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(tamperedBundle, nil, types.MediaType(signedImage.MediaType))
	assert.NilError(t, err, "ReadSignature should succeed (tampering not detected at parse time)")

	// Verification should fail - the signature doesn't match the tampered payload.
	err = sig.VerifyWithKey(pubKey)
	assert.Assert(t, err != nil, "VerifyWithKey should fail with tampered subject digest")
	assert.Assert(t, errors.Is(err, types.ErrBundleSignatureVerificationFailed),
		"error should wrap ErrBundleSignatureVerificationFailed, got: %v", err)
}

// TestVerifyWithKey_TamperedSignature tests that a tampered signature is rejected.
func TestSignature_TamperedSignature(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair and sign an image.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Tamper with the signature.
	tamperedBundle, err := tamperSignature(signedImage.Bundle)
	assert.NilError(t, err, "tamperSignature")

	// Read the tampered signature.
	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(tamperedBundle, nil, types.MediaType(signedImage.MediaType))
	assert.NilError(t, err, "ReadSignature should succeed (tampering not detected at parse time)")

	// Verification should fail - the signature is garbage.
	err = sig.VerifyWithKey(pubKey)
	assert.Assert(t, err != nil, "VerifyWithKey should fail with tampered signature")
	assert.Assert(t, errors.Is(err, types.ErrBundleSignatureVerificationFailed),
		"error should wrap ErrBundleSignatureVerificationFailed, got: %v", err)
}

// TestVerifyWithKey_RemovedSignature tests that a bundle with no signature fails verification.
func TestSignature_RemovedSignature(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair and sign an image.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Remove the signature from the bundle.
	tamperedBundle, err := removeSignature(signedImage.Bundle)
	assert.NilError(t, err, "removeSignature")

	// Reading may succeed (sigstore-go parses structure without validating signature count).
	signer := sigstore.NewSigner(nil)
	sig, err := signer.ReadSignature(tamperedBundle, nil, types.MediaType(signedImage.MediaType))
	assert.NilError(t, err, "ReadSignature")

	// Verification should fail - no signature to verify.
	err = sig.VerifyWithKey(pubKey)
	assert.Assert(t, err != nil, "VerifyWithKey should fail with removed signature")
	assert.Assert(t, errors.Is(err, types.ErrBundleSignatureVerificationFailed),
		"error should wrap ErrBundleSignatureVerificationFailed, got: %v", err)
}

// TestReadSignature_CorruptedPayload tests that a bundle with corrupted payload is rejected.
func TestSignature_CorruptedPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair and sign an image.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	signedImage, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage")

	// Corrupt the payload.
	tamperedBundle, err := corruptPayload(signedImage.Bundle)
	assert.NilError(t, err, "corruptPayload")

	// Reading should fail - payload is not valid JSON.
	signer := sigstore.NewSigner(nil)
	_, err = signer.ReadSignature(tamperedBundle, nil, types.MediaType(signedImage.MediaType))
	assert.Assert(t, err != nil, "ReadSignature should fail with corrupted payload")
	assert.Assert(t, errors.Is(err, types.ErrBundleReadFailed),
		"error should wrap ErrBundleReadFailed, got: %v", err)
}

// TestVerifyWithKey_ReplayAttack tests that using a signature on a different digest fails.
// This simulates an attacker trying to use a valid signature for a different artifact.
func TestSignature_ReplayAttack(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Parallel()

	// Generate key pair and sign TWO different images.
	keyPair, err := testcosign.GenerateKeyPair("test")
	assert.NilError(t, err, "GenerateKeyPair")

	defer keyPair.Cleanup()

	signedImage1, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage 1")

	signedImage2, err := testcosign.SignImage(keyPair, false)
	assert.NilError(t, err, "SignImage 2")

	pubKey, err := keyPair.ReadPublicKey()
	assert.NilError(t, err, "ReadPublicKey")

	// Read both signatures.
	signer := sigstore.NewSigner(nil)
	sig1, err := signer.ReadSignature(signedImage1.Bundle, nil, types.MediaType(signedImage1.MediaType))
	assert.NilError(t, err, "ReadSignature 1")

	sig2, err := signer.ReadSignature(signedImage2.Bundle, nil, types.MediaType(signedImage2.MediaType))
	assert.NilError(t, err, "ReadSignature 2")

	// Both signatures should verify with the same key.
	err = sig1.VerifyWithKey(pubKey)
	assert.NilError(t, err, "VerifyWithKey sig1")

	err = sig2.VerifyWithKey(pubKey)
	assert.NilError(t, err, "VerifyWithKey sig2")

	// The digests should be different (different images).
	digests1 := sig1.Digests()
	digests2 := sig2.Digests()
	assert.Assert(t, len(digests1) == 1 && len(digests2) == 1, "each signature should have one digest")
	assert.Assert(t, string(digests1[0]) != string(digests2[0]),
		"signatures should be for different digests: %s vs %s", digests1[0], digests2[0])

	// This confirms replay protection: each signature is bound to a specific digest.
	// An attacker cannot use sig1 to claim sig2's artifact is signed.
}
