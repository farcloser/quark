package sshprime_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/core/sshprime"
	"github.com/farcloser/quark/pkg/fault"
	testssh "github.com/farcloser/quark/testutil/ssh"
)

// generateSignerTestKey generates an ed25519 key pair and returns the private key
// and the SSH public key.
func generateSignerTestKey(t *testing.T) (ed25519.PrivateKey, ssh.PublicKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to convert public key: %v", err)
	}

	return priv, sshPub
}

// marshalSignerPrivateKeyToPEM marshals a private key to OpenSSH PEM format.
func marshalSignerPrivateKeyToPEM(t *testing.T, priv ed25519.PrivateKey, passphrase []byte) []byte {
	t.Helper()

	var (
		block *pem.Block
		err   error
	)

	if passphrase != nil {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", passphrase)
	} else {
		block, err = ssh.MarshalPrivateKey(priv, "")
	}

	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	return pem.EncodeToMemory(block)
}

func TestSignerFromKey_NilKey(t *testing.T) {
	t.Parallel()

	signer, err := sshprime.SignerFromKey(nil)

	if signer != nil {
		t.Error("expected nil signer for nil key")
	}

	if !errors.Is(err, sshprime.ErrSignerNilKey) {
		t.Errorf("expected ErrSignerNilKey, got: %v", err)
	}
}

func TestSignerFromKey_UnencryptedKey(t *testing.T) {
	t.Parallel()

	priv, expectedPubKey := generateSignerTestKey(t)
	pemBytes := marshalSignerPrivateKeyToPEM(t, priv, nil)

	key := &sshprime.Key{Bytes: pemBytes}

	signer, err := sshprime.SignerFromKey(key)
	if err != nil {
		t.Fatalf("SignerFromKey failed: %v", err)
	}

	if signer == nil {
		t.Fatal("expected non-nil signer")
	}

	// Verify the public key matches
	if ssh.FingerprintSHA256(signer.PublicKey()) != ssh.FingerprintSHA256(expectedPubKey) {
		t.Error("signer public key doesn't match original key")
	}
}

func TestSignerFromKey_EncryptedKeyWithPassphrase(t *testing.T) {
	t.Parallel()

	priv, expectedPubKey := generateSignerTestKey(t)
	passphrase := []byte("testpassphrase")
	pemBytes := marshalSignerPrivateKeyToPEM(t, priv, passphrase)

	key := &sshprime.Key{Bytes: pemBytes, Passphrase: passphrase}

	signer, err := sshprime.SignerFromKey(key)
	if err != nil {
		t.Fatalf("SignerFromKey failed: %v", err)
	}

	if signer == nil {
		t.Fatal("expected non-nil signer")
	}

	// Verify the public key matches
	if ssh.FingerprintSHA256(signer.PublicKey()) != ssh.FingerprintSHA256(expectedPubKey) {
		t.Error("signer public key doesn't match original key")
	}
}

func TestSignerFromKey_EncryptedKeyWithoutPassphrase(t *testing.T) {
	t.Parallel()

	priv, _ := generateSignerTestKey(t)
	passphrase := []byte("testpassphrase")
	pemBytes := marshalSignerPrivateKeyToPEM(t, priv, passphrase)

	key := &sshprime.Key{Bytes: pemBytes}

	signer, err := sshprime.SignerFromKey(key)

	if signer != nil {
		t.Error("expected nil signer for encrypted key without passphrase")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("expected fault.ErrInvalidArgument, got: %v", err)
	}
}

func TestSignerFromKey_EncryptedKeyWrongPassphrase(t *testing.T) {
	t.Parallel()

	priv, _ := generateSignerTestKey(t)
	passphrase := []byte("correctpassphrase")
	pemBytes := marshalSignerPrivateKeyToPEM(t, priv, passphrase)

	key := &sshprime.Key{Bytes: pemBytes, Passphrase: []byte("wrongpassphrase")}

	signer, err := sshprime.SignerFromKey(key)

	if signer != nil {
		t.Error("expected nil signer for wrong passphrase")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("expected fault.ErrInvalidArgument, got: %v", err)
	}
}

func TestSignerFromKey_InvalidKeyBytes(t *testing.T) {
	t.Parallel()

	key := &sshprime.Key{Bytes: []byte("not a valid key")}

	signer, err := sshprime.SignerFromKey(key)

	if signer != nil {
		t.Error("expected nil signer for invalid key bytes")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("expected fault.ErrInvalidArgument, got: %v", err)
	}
}

func TestSignerFromKey_EmptyKeyBytes(t *testing.T) {
	t.Parallel()

	key := &sshprime.Key{Bytes: []byte{}}

	signer, err := sshprime.SignerFromKey(key)

	if signer != nil {
		t.Error("expected nil signer for empty key bytes")
	}

	if !errors.Is(err, fault.ErrInvalidArgument) {
		t.Errorf("expected fault.ErrInvalidArgument, got: %v", err)
	}
}

//nolint:paralleltest // Modifies environment variables via SetEnv.
func TestSignerFromAgent_EmptyFingerprint_ReturnsFirstSigner(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Add multiple keys to the agent
	firstPubKey := testAgent.GenerateAndAddKey("first-key")
	testAgent.GenerateAndAddKey("second-key")

	signer, err := sshprime.SignerFromAgent("")
	if err != nil {
		t.Fatalf("SignerFromAgent failed: %v", err)
	}

	if signer == nil {
		t.Fatal("expected non-nil signer")
	}

	// Should return the first signer
	if ssh.FingerprintSHA256(signer.PublicKey()) != ssh.FingerprintSHA256(firstPubKey) {
		t.Error("expected first signer to be returned when fingerprint is empty")
	}
}

//nolint:paralleltest // Modifies environment variables via SetEnv.
func TestSignerFromAgent_MatchingFingerprint(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Add multiple keys to the agent
	testAgent.GenerateAndAddKey("first-key")
	secondPubKey := testAgent.GenerateAndAddKey("second-key")
	testAgent.GenerateAndAddKey("third-key")

	targetFingerprint := ssh.FingerprintSHA256(secondPubKey)

	signer, err := sshprime.SignerFromAgent(targetFingerprint)
	if err != nil {
		t.Fatalf("SignerFromAgent failed: %v", err)
	}

	if signer == nil {
		t.Fatal("expected non-nil signer")
	}

	// Should return the signer with matching fingerprint
	if ssh.FingerprintSHA256(signer.PublicKey()) != targetFingerprint {
		t.Error("signer fingerprint doesn't match requested fingerprint")
	}
}

//nolint:paralleltest // Modifies environment variables via SetEnv.
func TestSignerFromAgent_NonMatchingFingerprint(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Add a key to the agent
	testAgent.GenerateAndAddKey("test-key")

	// Request a non-existent fingerprint
	signer, err := sshprime.SignerFromAgent("SHA256:nonexistentfingerprint")

	if signer != nil {
		t.Error("expected nil signer for non-matching fingerprint")
	}

	if !errors.Is(err, fault.ErrNotFound) {
		t.Errorf("expected fault.ErrNotFound, got: %v", err)
	}
}

//nolint:paralleltest // Modifies environment variables via SetEnv.
func TestSignerFromAgent_NoSignersInAgent(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Don't add any keys - agent is empty

	signer, err := sshprime.SignerFromAgent("")

	if signer != nil {
		t.Error("expected nil signer when agent has no keys")
	}

	if !errors.Is(err, fault.ErrNotFound) {
		t.Errorf("expected fault.ErrNotFound, got: %v", err)
	}
}

//nolint:paralleltest // Modifies environment variables via SetEnv.
func TestSignerFromAgent_NoSignersWithFingerprint(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Don't add any keys - agent is empty

	signer, err := sshprime.SignerFromAgent("SHA256:somefingerprint")

	if signer != nil {
		t.Error("expected nil signer when agent has no keys")
	}

	if !errors.Is(err, fault.ErrNotFound) {
		t.Errorf("expected fault.ErrNotFound, got: %v", err)
	}
}

func TestSignerFromAgent_NoAgentAvailable(t *testing.T) {
	// Set invalid agent socket
	t.Setenv("SSH_AUTH_SOCK", "/nonexistent/socket")
	sshprime.GetAgent().Close()

	signer, err := sshprime.SignerFromAgent("")

	if signer != nil {
		t.Error("expected nil signer when agent is not available")
	}

	if err == nil {
		t.Error("expected error when agent is not available")
	}
}
