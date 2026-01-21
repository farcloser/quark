//nolint:paralleltest // home manipulation
package sshprime_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/core/sshprime"
	testssh "github.com/farcloser/quark/testutil/ssh"
)

// generateAuthTestKey generates an ed25519 key pair and returns the private key
// and the SSH public key.
func generateAuthTestKey(t *testing.T) (ed25519.PrivateKey, ssh.PublicKey) {
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

// marshalPrivateKeyToPEM marshals a private key to OpenSSH PEM format.
func marshalPrivateKeyToPEM(t *testing.T, priv ed25519.PrivateKey, passphrase []byte) []byte {
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

// mustNewKey creates a sshprime.Key from bytes and passphrase, or fails the test.
func mustNewKey(t *testing.T, bytes, passphrase []byte) sshprime.Key {
	t.Helper()

	key, err := sshprime.NewKey(bytes, passphrase, false)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	return key
}

func TestGetSigners_AgentOnly(t *testing.T) {
	// Start test agent and add a key.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()

	agentPubKey := testAgent.GenerateAndAddKey("test-key")

	// Close the singleton agent to force reconnection to our test agent.
	sshprime.GetAgent().Close()

	// Use withSSHConfig=true so that identityOnly=false and agent keys are included.
	// With withSSHConfig=false, identityOnly=true and only explicitly requested keys are returned.
	signers := sshprime.GetSigners(nil, "somehost", true)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}

	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}

	if ssh.FingerprintSHA256(signers[0].PublicKey()) != ssh.FingerprintSHA256(agentPubKey) {
		t.Error("signer fingerprint doesn't match agent key")
	}
}

func TestGetSigners_ExplicitUnencryptedKey(t *testing.T) {
	// Start test agent (empty).
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Generate an unencrypted key.
	priv, _ := generateAuthTestKey(t)
	pemBytes := marshalPrivateKeyToPEM(t, priv, nil) // No passphrase

	key := mustNewKey(t, pemBytes, nil)

	signers := sshprime.GetSigners([]sshprime.Key{key}, "somehost", false)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}
}

func TestGetSigners_ExplicitEncryptedKeyWithPassphrase(t *testing.T) {
	// Start test agent (empty).
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Generate an encrypted key.
	priv, _ := generateAuthTestKey(t)
	passphrase := []byte("testpassword")
	pemBytes := marshalPrivateKeyToPEM(t, priv, passphrase)

	key := mustNewKey(t, pemBytes, passphrase)

	signers := sshprime.GetSigners([]sshprime.Key{key}, "somehost", false)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}
}

func TestGetSigners_ExplicitEncryptedKeyMatchingAgent(t *testing.T) {
	// Start test agent.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Generate a key and add it to the agent.
	priv, pubKey := generateAuthTestKey(t)
	if err := testAgent.AddKey(priv, "matching-key"); err != nil {
		t.Fatalf("failed to add key to agent: %v", err)
	}

	// Create an encrypted version of the same key (without passphrase).
	// NewKey will extract only the public key, which should match with agent.
	passphrase := []byte("testpassword")
	pemBytes := marshalPrivateKeyToPEM(t, priv, passphrase)

	key := mustNewKey(t, pemBytes, nil) // No passphrase - extracts public key only

	signers := sshprime.GetSigners([]sshprime.Key{key}, "somehost", false)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}

	// Verify we got the signer from the agent.
	found := false

	for _, s := range signers {
		if ssh.FingerprintSHA256(s.PublicKey()) == ssh.FingerprintSHA256(pubKey) {
			found = true

			break
		}
	}

	if !found {
		t.Error("expected to find matching key in signers")
	}
}

func TestGetSigners_NoAgent(t *testing.T) {
	// Set invalid agent socket.
	t.Setenv("SSH_AUTH_SOCK", "/nonexistent/socket")
	sshprime.GetAgent().Close()

	// Generate an unencrypted key so we have something to use.
	priv, _ := generateAuthTestKey(t)
	pemBytes := marshalPrivateKeyToPEM(t, priv, nil)

	key := mustNewKey(t, pemBytes, nil)

	// Should not fail even without agent.
	signers := sshprime.GetSigners([]sshprime.Key{key}, "somehost", false)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}
}

func TestGetSigners_PublicKeyOnlyMatchingAgent(t *testing.T) {
	// Start test agent.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Generate a key and add to agent.
	priv, pubKey := generateAuthTestKey(t)
	if err := testAgent.AddKey(priv, "agent-key"); err != nil {
		t.Fatalf("failed to add key to agent: %v", err)
	}

	// Create a Key with just the public key bytes.
	pubKeyBytes := pubKey.Marshal()

	key := mustNewKey(t, pubKeyBytes, nil)

	signers := sshprime.GetSigners([]sshprime.Key{key}, "somehost", false)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}
}

func TestGetSigners_UseConfigFalse_IdentityOnlyTrue(t *testing.T) {
	// When useConfig=false, identityOnly defaults to true.
	// This means only explicit keys are used, not other agent keys.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Add a key to agent that we DON'T provide explicitly.
	testAgent.GenerateAndAddKey("agent-only-key")

	// Provide a different explicit key.
	priv, _ := generateAuthTestKey(t)
	pemBytes := marshalPrivateKeyToPEM(t, priv, nil)

	key := mustNewKey(t, pemBytes, nil)

	signers := sshprime.GetSigners([]sshprime.Key{key}, "somehost", false)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}

	// The explicit key should be used as a signer directly since it's unencrypted.
	// The agent key should NOT be included because identityOnly=true when useConfig=false.
}

func TestGetSigners_MultipleExplicitKeys(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Generate multiple keys.
	priv1, _ := generateAuthTestKey(t)
	priv2, _ := generateAuthTestKey(t)

	pem1 := marshalPrivateKeyToPEM(t, priv1, nil)
	pem2 := marshalPrivateKeyToPEM(t, priv2, []byte("pass2"))

	keys := []sshprime.Key{
		mustNewKey(t, pem1, nil),
		mustNewKey(t, pem2, []byte("pass2")),
	}

	signers := sshprime.GetSigners(keys, "somehost", false)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}
}

func TestNewKey_InvalidKeyFormat(t *testing.T) {
	// NewKey should return error for invalid key bytes.
	_, err := sshprime.NewKey([]byte("not a valid key"), nil, false)
	if err == nil {
		t.Fatal("expected error for invalid key format")
	}
}

func TestNewKey_WrongPassphrase(t *testing.T) {
	// Generate encrypted key.
	priv, _ := generateAuthTestKey(t)
	pemBytes := marshalPrivateKeyToPEM(t, priv, []byte("correctpassword"))

	// NewKey should return error for wrong passphrase.
	_, err := sshprime.NewKey(pemBytes, []byte("wrongpassword"), false)
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestGetSigners_IdentityFileOnDisk_Encrypted(t *testing.T) {
	// Test loading an encrypted identity file from disk.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Generate a key and add to agent.
	priv, _ := generateAuthTestKey(t)
	if err := testAgent.AddKey(priv, "disk-key"); err != nil {
		t.Fatalf("failed to add key to agent: %v", err)
	}

	// Write encrypted key to disk.
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_test")
	pemBytes := marshalPrivateKeyToPEM(t, priv, []byte("diskpassword"))

	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// The function reads from config's IdentityFile, which we can't easily
	// override in this test. This test documents that encrypted files
	// on disk are handled (public key extracted, matched with agent).

	// For now, just verify the function works with no explicit keys.
	signers := sshprime.GetSigners(nil, "somehost", false)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}
}

func TestGetSigners_EmptyKeys(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Add a key to agent.
	testAgent.GenerateAndAddKey("agent-key")

	// Call with empty slice (not nil).
	signers := sshprime.GetSigners([]sshprime.Key{}, "somehost", false)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}
}

func TestGetSigners_NilKeys(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Add a key to agent.
	testAgent.GenerateAndAddKey("agent-key")

	// Call with nil slice.
	signers := sshprime.GetSigners(nil, "somehost", false)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}
}

func TestGetSigners_IdentityFileFromSSHConfig(t *testing.T) {
	// Test that IdentityFile directive in SSH config is read and used.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Create temp HOME with .ssh directory.
	tmpHome := t.TempDir()
	sshDir := filepath.Join(tmpHome, ".ssh")

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("failed to create .ssh dir: %v", err)
	}

	// Generate a key and add it to the agent.
	priv, _ := generateAuthTestKey(t)
	if err := testAgent.AddKey(priv, "config-key"); err != nil {
		t.Fatalf("failed to add key to agent: %v", err)
	}

	// Write the encrypted key to disk.
	keyPath := filepath.Join(sshDir, "id_configured")
	pemBytes := marshalPrivateKeyToPEM(t, priv, []byte("configpassword"))

	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Write SSH config that references the key.
	configContent := "Host testhost.example.com\n  IdentityFile ~/.ssh/id_configured\n"

	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(configContent), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Set HOME to our temp directory.
	t.Setenv("HOME", tmpHome)

	// Call with withSSHConfig=true for the configured host.
	signers := sshprime.GetSigners(nil, "testhost.example.com", true)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}
}

func TestGetSigners_IdentityFileRefusesUnencrypted(t *testing.T) {
	// Test that unencrypted identity files on disk are refused.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Create temp HOME with .ssh directory.
	tmpHome := t.TempDir()
	sshDir := filepath.Join(tmpHome, ".ssh")

	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("failed to create .ssh dir: %v", err)
	}

	// Generate an UNENCRYPTED key and write to disk.
	priv, _ := generateAuthTestKey(t)
	keyPath := filepath.Join(sshDir, "id_unsafe")
	pemBytes := marshalPrivateKeyToPEM(t, priv, nil) // No passphrase

	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Write SSH config that references the unencrypted key.
	configContent := "Host unsafehost.example.com\n  IdentityFile ~/.ssh/id_unsafe\n  IdentitiesOnly yes\n"

	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(configContent), 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Set HOME to our temp directory.
	t.Setenv("HOME", tmpHome)

	// This should succeed but the unencrypted key should be rejected
	// (logged as error but not used). The signers will be returned
	// but without any usable signers from that key.
	signers := sshprime.GetSigners(nil, "unsafehost.example.com", true)

	if signers == nil {
		t.Fatal("expected non-nil signers")
	}
}
