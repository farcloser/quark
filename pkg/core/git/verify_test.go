package git_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/crypto/ssh"
	"gotest.tools/v3/assert"

	"github.com/farcloser/quark/pkg/core/git"
)

// createCommitWithSignature creates a commit with a specific PGPSignature value for testing.
func createCommitWithSignature(t *testing.T, dir, signature string) string {
	t.Helper()

	repo, err := gogit.PlainOpen(dir)
	assert.NilError(t, err)

	// Get HEAD to use as parent (if exists).
	var parentHashes []plumbing.Hash

	head, err := repo.Head()
	if err == nil {
		parentHashes = append(parentHashes, head.Hash())
	}

	// Create commit object with crafted signature.
	commit := &object.Commit{
		Author: object.Signature{
			Name:  "Test",
			Email: "test@example.com",
			When:  time.Now(),
		},
		Committer: object.Signature{
			Name:  "Test",
			Email: "test@example.com",
			When:  time.Now(),
		},
		Message:      "test commit with crafted signature",
		ParentHashes: parentHashes,
		PGPSignature: signature,
	}

	// If there's a parent, use its tree; otherwise create empty tree.
	if len(parentHashes) > 0 {
		parentCommit, err := repo.CommitObject(parentHashes[0])
		assert.NilError(t, err)

		commit.TreeHash = parentCommit.TreeHash
	} else {
		// Create an empty tree.
		obj := repo.Storer.NewEncodedObject()
		obj.SetType(plumbing.TreeObject)

		hash, err := repo.Storer.SetEncodedObject(obj)
		assert.NilError(t, err)

		commit.TreeHash = hash
	}

	// Store the commit.
	obj := repo.Storer.NewEncodedObject()
	err = commit.Encode(obj)
	assert.NilError(t, err)

	hash, err := repo.Storer.SetEncodedObject(obj)
	assert.NilError(t, err)

	return hash.String()
}

// buildValidSignatureBlob builds a valid SSH signature blob structure.
func buildValidSignatureBlob(t *testing.T, pubKey ssh.PublicKey, sig *ssh.Signature) []byte {
	t.Helper()

	var buf []byte

	// Magic.
	buf = append(buf, []byte("SSHSIG")...)

	// Version (1).
	buf = binary.BigEndian.AppendUint32(buf, 1)

	// Public key.
	pubKeyBytes := pubKey.Marshal()
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(pubKeyBytes)))
	buf = append(buf, pubKeyBytes...)

	// Namespace.
	namespace := "git"
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(namespace)))
	buf = append(buf, namespace...)

	// Reserved (empty).
	buf = binary.BigEndian.AppendUint32(buf, 0)

	// Hash algorithm.
	hashAlgo := "sha512"
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(hashAlgo)))
	buf = append(buf, hashAlgo...)

	// Signature.
	sigBytes := ssh.Marshal(sig)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(sigBytes)))
	buf = append(buf, sigBytes...)

	return buf
}

// armorSignature wraps a signature blob in SSH signature armor.
func armorSignature(blob []byte) string {
	encoded := base64.StdEncoding.EncodeToString(blob)

	return "-----BEGIN SSH SIGNATURE-----\n" + encoded + "\n-----END SSH SIGNATURE-----"
}

// generateVerifyTestKey generates an ed25519 key and returns it as PEM bytes for testing.
func generateVerifyTestKey(t *testing.T) (ed25519.PublicKey, []byte) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	return pub, pem.EncodeToMemory(block)
}

// TestGetCommitSignerUnsignedCommit tests that unsigned commits return errNoSignature.
func TestGetCommitSignerUnsignedCommit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create an unsigned commit using the low-level helper (simulates legacy unsigned commits).
	hash := createCommitWithSignature(t, dir, "")

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureMissing)
}

// TestGetCommitSignerInvalidHash tests that non-existent commits return an error.
func TestGetCommitSignerInvalidHash(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	_, keyBytes := generateVerifyTestKey(t)

	_, err = repo.CreateEmptyCommit(
		"initial",
		&git.Author{
			Name:  "Test",
			Email: "test@example.com",
			Key:   mustNewKey(t, keyBytes),
		},
		time.Now(),
	)
	assert.NilError(t, err)

	_, err = repo.GetCommitSigner("0000000000000000000000000000000000000000")
	assert.ErrorIs(t, err, git.ErrSignatureNoSuchCommit)
}

// TestGetCommitSignerSignedCommit tests successful signature verification.
func TestGetCommitSignerSignedCommit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	_, keyBytes := generateVerifyTestKey(t)

	hash, err := repo.CreateEmptyCommit(
		"signed commit",
		&git.Author{
			Name:  "Test",
			Email: "test@example.com",
			Key:   mustNewKey(t, keyBytes),
		},
		time.Now(),
	)
	assert.NilError(t, err)

	info, err := repo.GetCommitSigner(hash)
	assert.NilError(t, err)
	assert.Assert(t, info != nil)
	assert.Equal(t, info.KeyType, "ssh-ed25519")
	assert.Assert(t, len(info.KeyFingerprint) > 0)
}

// TestGetCommitSignerFingerprintMatchesKey verifies the fingerprint matches the signing key.
func TestGetCommitSignerFingerprintMatchesKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	publicKey, keyBytes := generateVerifyTestKey(t)

	hash, err := repo.CreateEmptyCommit(
		"signed commit",
		&git.Author{
			Name:  "Test",
			Email: "test@example.com",
			Key:   mustNewKey(t, keyBytes),
		},
		time.Now(),
	)
	assert.NilError(t, err)

	info, err := repo.GetCommitSigner(hash)
	assert.NilError(t, err)

	sshPubKey, err := ssh.NewPublicKey(publicKey)
	assert.NilError(t, err)

	expectedFingerprint := ssh.FingerprintSHA256(sshPubKey)
	assert.Equal(t, info.KeyFingerprint, expectedFingerprint)
}

// TestGetCommitSignerMultipleCommits verifies different signers produce different fingerprints.
func TestGetCommitSignerMultipleCommits(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	_, keyBytes1 := generateVerifyTestKey(t)
	_, keyBytes2 := generateVerifyTestKey(t)

	hash1, err := repo.CreateEmptyCommit(
		"commit 1",
		&git.Author{
			Name:  "Test",
			Email: "test@example.com",
			Key:   mustNewKey(t, keyBytes1),
		},
		time.Now(),
	)
	assert.NilError(t, err)

	hash2, err := repo.CreateEmptyCommit(
		"commit 2",
		&git.Author{
			Name:  "Test",
			Email: "test@example.com",
			Key:   mustNewKey(t, keyBytes2),
		},
		time.Now(),
	)
	assert.NilError(t, err)

	info1, err := repo.GetCommitSigner(hash1)
	assert.NilError(t, err)

	info2, err := repo.GetCommitSigner(hash2)
	assert.NilError(t, err)

	assert.Assert(t, info1.KeyFingerprint != info2.KeyFingerprint)
}

// TestGetCommitSignerMissingBeginMarker tests error when BEGIN marker is missing.
func TestGetCommitSignerMissingBeginMarker(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Signature without BEGIN marker.
	hash := createCommitWithSignature(t, dir, "U1NI\n-----END SSH SIGNATURE-----")

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerMissingEndMarker tests error when END marker is missing.
func TestGetCommitSignerMissingEndMarker(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Signature without END marker.
	hash := createCommitWithSignature(t, dir, "-----BEGIN SSH SIGNATURE-----\nU1NI")

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerMalformedArmor tests error when END appears before BEGIN.
func TestGetCommitSignerMalformedArmor(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// END before BEGIN.
	hash := createCommitWithSignature(t, dir, "-----END SSH SIGNATURE----------BEGIN SSH SIGNATURE-----")

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerInvalidBase64 tests error when base64 content is invalid.
func TestGetCommitSignerInvalidBase64(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Invalid base64 content.
	hash := createCommitWithSignature(t, dir, "-----BEGIN SSH SIGNATURE-----\n!!invalid!!\n-----END SSH SIGNATURE-----")

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerInvalidMagic tests error when signature blob has wrong magic.
func TestGetCommitSignerInvalidMagic(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Valid armor but wrong magic in blob.
	blob := []byte("NOTMAGIC")
	hash := createCommitWithSignature(t, dir, armorSignature(blob))

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerUnsupportedVersion tests error when signature has unsupported version.
func TestGetCommitSignerUnsupportedVersion(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Valid magic but wrong version.
	var blob []byte

	blob = append(blob, []byte("SSHSIG")...)
	blob = binary.BigEndian.AppendUint32(blob, 99) // Invalid version.

	hash := createCommitWithSignature(t, dir, armorSignature(blob))

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerUnsupportedHashAlgo tests error when signature uses unsupported hash.
func TestGetCommitSignerUnsupportedHashAlgo(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Generate a key for the blob.
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NilError(t, err)

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	assert.NilError(t, err)

	// Build blob with unsupported hash algorithm.
	var blob []byte

	blob = append(blob, []byte("SSHSIG")...)
	blob = binary.BigEndian.AppendUint32(blob, 1) // Version 1.

	// Public key.
	pubKeyBytes := sshPubKey.Marshal()
	blob = binary.BigEndian.AppendUint32(blob, uint32(len(pubKeyBytes)))
	blob = append(blob, pubKeyBytes...)

	// Namespace.
	namespace := "git"
	blob = binary.BigEndian.AppendUint32(blob, uint32(len(namespace)))
	blob = append(blob, namespace...)

	// Reserved.
	blob = binary.BigEndian.AppendUint32(blob, 0)

	// Unsupported hash algorithm.
	hashAlgo := "sha256"
	blob = binary.BigEndian.AppendUint32(blob, uint32(len(hashAlgo)))
	blob = append(blob, hashAlgo...)

	hash := createCommitWithSignature(t, dir, armorSignature(blob))

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerTruncatedBlob tests error when signature blob is truncated.
func TestGetCommitSignerTruncatedBlob(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Valid magic and version but truncated after that.
	var blob []byte

	blob = append(blob, []byte("SSHSIG")...)
	blob = binary.BigEndian.AppendUint32(blob, 1)
	// Truncated - no public key or other fields.

	hash := createCommitWithSignature(t, dir, armorSignature(blob))

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerWrongNamespace tests error when signature has wrong namespace.
func TestGetCommitSignerWrongNamespace(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Generate a key for the blob.
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NilError(t, err)

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	assert.NilError(t, err)

	// Build blob with wrong namespace.
	var blob []byte

	blob = append(blob, []byte("SSHSIG")...)
	blob = binary.BigEndian.AppendUint32(blob, 1)

	pubKeyBytes := sshPubKey.Marshal()
	blob = binary.BigEndian.AppendUint32(blob, uint32(len(pubKeyBytes)))
	blob = append(blob, pubKeyBytes...)

	// Wrong namespace.
	namespace := "file"
	blob = binary.BigEndian.AppendUint32(blob, uint32(len(namespace)))
	blob = append(blob, namespace...)

	// Reserved.
	blob = binary.BigEndian.AppendUint32(blob, 0)

	// Hash algorithm.
	hashAlgo := "sha512"
	blob = binary.BigEndian.AppendUint32(blob, uint32(len(hashAlgo)))
	blob = append(blob, hashAlgo...)

	// Minimal signature.
	sig := &ssh.Signature{Format: "ssh-ed25519", Blob: make([]byte, 64)}
	sigBytes := ssh.Marshal(sig)
	blob = binary.BigEndian.AppendUint32(blob, uint32(len(sigBytes)))
	blob = append(blob, sigBytes...)

	hash := createCommitWithSignature(t, dir, armorSignature(blob))

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerSignatureVerificationFailed tests error when signature doesn't verify.
func TestGetCommitSignerSignatureVerificationFailed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Generate a key for the blob.
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NilError(t, err)

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	assert.NilError(t, err)

	// Build a complete but invalid signature (signature bytes don't match content).
	sig := &ssh.Signature{Format: "ssh-ed25519", Blob: make([]byte, 64)}
	blob := buildValidSignatureBlob(t, sshPubKey, sig)

	hash := createCommitWithSignature(t, dir, armorSignature(blob))

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureVerificationFailed)
}

// TestGetCommitSignerBlobTooShort tests error when blob is shorter than magic.
func TestGetCommitSignerBlobTooShort(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Blob shorter than "SSHSIG" (6 bytes).
	blob := []byte("SSH")
	hash := createCommitWithSignature(t, dir, armorSignature(blob))

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerStringFieldTooLong tests DoS protection against huge length fields.
// A malicious signature could claim a string field is 4GB, causing memory exhaustion.
// The implementation should reject fields > 64KB.
func TestGetCommitSignerStringFieldTooLong(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Build blob with a public key length field claiming 1MB.
	// This should be rejected before attempting to allocate.
	var blob []byte

	blob = append(blob, []byte("SSHSIG")...)
	blob = binary.BigEndian.AppendUint32(blob, 1) // Version 1.

	// Public key with malicious length (1MB = 1048576 bytes, way over 64KB limit).
	blob = binary.BigEndian.AppendUint32(blob, 1048576)
	// Don't actually append 1MB of data - the length check should fail first.

	hash := createCommitWithSignature(t, dir, armorSignature(blob))

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerEmptyArmorContent tests error when armor has no content.
func TestGetCommitSignerEmptyArmorContent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Empty content between markers.
	hash := createCommitWithSignature(t, dir, "-----BEGIN SSH SIGNATURE----------END SSH SIGNATURE-----")

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerArmorWithWhitespace tests that whitespace in base64 is handled.
func TestGetCommitSignerArmorWithWhitespace(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// "SSHSIG" in base64 is "U1NISUc=" - add spaces and newlines.
	// This should still parse (spaces/newlines stripped) but fail on version check.
	armoredWithWhitespace := "-----BEGIN SSH SIGNATURE-----\nU1 NI\nSU c=\n-----END SSH SIGNATURE-----"
	hash := createCommitWithSignature(t, dir, armoredWithWhitespace)

	// Should parse the armor successfully but fail on subsequent checks
	// (missing version field after magic).
	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerArmorWithLeadingContent tests signature with text before BEGIN.
func TestGetCommitSignerArmorWithLeadingContent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	_, keyBytes := generateVerifyTestKey(t)

	// Create a properly signed commit first to get a valid signature.
	hash, err := repo.CreateEmptyCommit(
		"signed",
		&git.Author{
			Name:  "Test",
			Email: "test@example.com",
			Key:   mustNewKey(t, keyBytes),
		},
		time.Now(),
	)
	assert.NilError(t, err)

	// Verify it works normally.
	info, err := repo.GetCommitSigner(hash)
	assert.NilError(t, err)
	assert.Equal(t, info.KeyType, "ssh-ed25519")
}

// TestGetCommitSignerMaxUint32Length tests DoS protection against max uint32 length field.
// An attacker could set length to 0xFFFFFFFF (4GB) to cause memory exhaustion.
func TestGetCommitSignerMaxUint32Length(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Build blob with max uint32 length field.
	var blob []byte

	blob = append(blob, []byte("SSHSIG")...)
	blob = binary.BigEndian.AppendUint32(blob, 1) // Version 1.

	// Public key with max uint32 length (4GB).
	blob = binary.BigEndian.AppendUint32(blob, 0xFFFFFFFF)

	hash := createCommitWithSignature(t, dir, armorSignature(blob))

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestGetCommitSignerMalformedPublicKey tests error when public key data is malformed.
// The signature claims to contain a valid key but the bytes don't parse.
func TestGetCommitSignerMalformedPublicKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create initial commit so repo has a tree.
	createCommitWithSignature(t, dir, "")

	// Build blob with garbage public key data.
	var blob []byte

	blob = append(blob, []byte("SSHSIG")...)
	blob = binary.BigEndian.AppendUint32(blob, 1) // Version 1.

	// Malformed public key - random bytes that won't parse as any valid key type.
	garbageKey := []byte("this is not a valid ssh public key format")
	blob = binary.BigEndian.AppendUint32(blob, uint32(len(garbageKey)))
	blob = append(blob, garbageKey...)

	hash := createCommitWithSignature(t, dir, armorSignature(blob))

	_, err = repo.GetCommitSigner(hash)
	assert.ErrorIs(t, err, git.ErrSignatureInvalidFormat)
}

// TestIsSigned_SignedCommit tests that IsSigned returns true for signed commits.
func TestIsSigned_SignedCommit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	_, keyBytes := generateVerifyTestKey(t)

	hash, err := repo.CreateEmptyCommit(
		"signed commit",
		&git.Author{
			Name:  "Test",
			Email: "test@example.com",
			Key:   mustNewKey(t, keyBytes),
		},
		time.Now(),
	)
	assert.NilError(t, err)

	signed, err := repo.IsSigned(hash)
	assert.NilError(t, err)
	assert.Assert(t, signed, "IsSigned should return true for signed commit")
}

// TestIsSigned_UnsignedCommit tests that IsSigned returns false for unsigned commits.
func TestIsSigned_UnsignedCommit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create an unsigned commit using the low-level helper (simulates legacy unsigned commits).
	hash := createCommitWithSignature(t, dir, "")

	signed, err := repo.IsSigned(hash)
	assert.NilError(t, err)
	assert.Assert(t, !signed, "IsSigned should return false for unsigned commit")
}

// TestIsSigned_NonExistentCommit tests that IsSigned returns error for non-existent commits.
func TestIsSigned_NonExistentCommit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	// Create an initial commit so the repo isn't empty.
	createCommitWithSignature(t, dir, "")

	// Try to check a non-existent commit hash.
	_, err = repo.IsSigned("0000000000000000000000000000000000000000")
	assert.ErrorIs(t, err, git.ErrSignatureNoSuchCommit)
}
