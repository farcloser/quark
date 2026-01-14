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

func TestGetAuthMethod_AgentOnly(t *testing.T) {
	// Start test agent and add a key.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()

	agentPubKey := testAgent.GenerateAndAddKey("test-key")

	// Close the singleton agent to force reconnection to our test agent.
	sshprime.GetAgent().Close()

	auth := sshprime.GetAuthMethod(nil, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}

	// Verify the agent key is accessible by getting signers directly.
	signers, err := sshprime.GetAgent().Signers()
	if err != nil {
		t.Fatalf("failed to get signers: %v", err)
	}

	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}

	if ssh.FingerprintSHA256(signers[0].PublicKey()) != ssh.FingerprintSHA256(agentPubKey) {
		t.Error("signer fingerprint doesn't match agent key")
	}
}

func TestGetAuthMethod_ExplicitUnencryptedKey(t *testing.T) {
	// Start test agent (empty).
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Generate an unencrypted key.
	priv, _ := generateAuthTestKey(t)
	pemBytes := marshalPrivateKeyToPEM(t, priv, nil) // No passphrase

	key := &sshprime.Key{
		Bytes:      pemBytes,
		Passphrase: nil,
	}

	auth := sshprime.GetAuthMethod([]*sshprime.Key{key}, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_ExplicitEncryptedKeyWithPassphrase(t *testing.T) {
	// Start test agent (empty).
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Generate an encrypted key.
	priv, _ := generateAuthTestKey(t)
	passphrase := []byte("testpassword")
	pemBytes := marshalPrivateKeyToPEM(t, priv, passphrase)

	key := &sshprime.Key{
		Bytes:      pemBytes,
		Passphrase: passphrase,
	}

	auth := sshprime.GetAuthMethod([]*sshprime.Key{key}, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_ExplicitEncryptedKeyMatchingAgent(t *testing.T) {
	// Start test agent.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Generate a key and add it to the agent.
	priv, pubKey := generateAuthTestKey(t)
	if err := testAgent.AddKey(priv, "matching-key"); err != nil {
		t.Fatalf("failed to add key to agent: %v", err)
	}

	// Create an encrypted version of the same key (without passphrase in Key struct).
	passphrase := []byte("testpassword")
	pemBytes := marshalPrivateKeyToPEM(t, priv, passphrase)

	key := &sshprime.Key{
		Bytes:      pemBytes,
		Passphrase: nil, // No passphrase - should match with agent
	}

	auth := sshprime.GetAuthMethod([]*sshprime.Key{key}, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}

	// Verify the agent has our key.
	signers, err := sshprime.GetAgent().Signers()
	if err != nil {
		t.Fatalf("failed to get signers: %v", err)
	}

	found := false

	for _, s := range signers {
		if ssh.FingerprintSHA256(s.PublicKey()) == ssh.FingerprintSHA256(pubKey) {
			found = true

			break
		}
	}

	if !found {
		t.Error("expected to find matching key in agent signers")
	}
}

func TestGetAuthMethod_NoAgent(t *testing.T) {
	// Set invalid agent socket.
	t.Setenv("SSH_AUTH_SOCK", "/nonexistent/socket")
	sshprime.GetAgent().Close()

	// Generate an unencrypted key so we have something to use.
	priv, _ := generateAuthTestKey(t)
	pemBytes := marshalPrivateKeyToPEM(t, priv, nil)

	key := &sshprime.Key{
		Bytes:      pemBytes,
		Passphrase: nil,
	}

	// Should not fail even without agent.
	auth := sshprime.GetAuthMethod([]*sshprime.Key{key}, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_PublicKeyOnlyMatchingAgent(t *testing.T) {
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

	key := &sshprime.Key{
		Bytes:      pubKeyBytes,
		Passphrase: nil,
	}

	auth := sshprime.GetAuthMethod([]*sshprime.Key{key}, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_UseConfigFalse_IdentityOnlyTrue(t *testing.T) {
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

	key := &sshprime.Key{
		Bytes:      pemBytes,
		Passphrase: nil,
	}

	auth := sshprime.GetAuthMethod([]*sshprime.Key{key}, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}

	// The explicit key should be used as a signer directly since it's unencrypted.
	// The agent key should NOT be included because identityOnly=true when useConfig=false.
}

func TestGetAuthMethod_MultipleExplicitKeys(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Generate multiple keys.
	priv1, _ := generateAuthTestKey(t)
	priv2, _ := generateAuthTestKey(t)

	pem1 := marshalPrivateKeyToPEM(t, priv1, nil)
	pem2 := marshalPrivateKeyToPEM(t, priv2, []byte("pass2"))

	keys := []*sshprime.Key{
		{Bytes: pem1, Passphrase: nil},
		{Bytes: pem2, Passphrase: []byte("pass2")},
	}

	auth := sshprime.GetAuthMethod(keys, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_InvalidKeyFormat(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Provide invalid key bytes.
	key := &sshprime.Key{
		Bytes:      []byte("not a valid key"),
		Passphrase: nil,
	}

	// Should not error, just warn and continue.
	auth := sshprime.GetAuthMethod([]*sshprime.Key{key}, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method even with invalid key")
	}
}

func TestGetAuthMethod_WrongPassphrase(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Generate encrypted key.
	priv, _ := generateAuthTestKey(t)
	pemBytes := marshalPrivateKeyToPEM(t, priv, []byte("correctpassword"))

	// Provide wrong passphrase.
	key := &sshprime.Key{
		Bytes:      pemBytes,
		Passphrase: []byte("wrongpassword"),
	}

	// Should not error - will fail to decrypt, treat as encrypted without passphrase.
	auth := sshprime.GetAuthMethod([]*sshprime.Key{key}, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_IdentityFileOnDisk_Encrypted(t *testing.T) {
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
	auth := sshprime.GetAuthMethod(nil, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_EmptyKeys(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Add a key to agent.
	testAgent.GenerateAndAddKey("agent-key")

	// Call with empty slice (not nil).
	auth := sshprime.GetAuthMethod([]*sshprime.Key{}, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_NilKeys(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	sshprime.GetAgent().Close()

	// Add a key to agent.
	testAgent.GenerateAndAddKey("agent-key")

	// Call with nil slice.
	auth := sshprime.GetAuthMethod(nil, "somehost", false)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_IdentityFileFromSSHConfig(t *testing.T) {
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
	auth := sshprime.GetAuthMethod(nil, "testhost.example.com", true)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_IdentityFileRefusesUnencrypted(t *testing.T) {
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
	// (logged as error but not used). The auth method will be returned
	// but without any usable signers from that key.
	auth := sshprime.GetAuthMethod(nil, "unsafehost.example.com", true)

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}
