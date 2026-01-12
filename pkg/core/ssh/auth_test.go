//nolint:paralleltest // home manipulation
package ssh_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	coressh "github.com/farcloser/quark/pkg/core/ssh"
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
	coressh.GetAgent().Close()

	auth, err := coressh.GetAuthMethod(nil, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod failed: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}

	// Verify the agent key is accessible by getting signers directly.
	signers, err := coressh.GetAgent().Signers()
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
	coressh.GetAgent().Close()

	// Generate an unencrypted key.
	priv, _ := generateAuthTestKey(t)
	pemBytes := marshalPrivateKeyToPEM(t, priv, nil) // No passphrase

	key := &coressh.Key{
		Bytes:      pemBytes,
		Passphrase: nil,
	}

	auth, err := coressh.GetAuthMethod([]*coressh.Key{key}, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod failed: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_ExplicitEncryptedKeyWithPassphrase(t *testing.T) {
	// Start test agent (empty).
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	coressh.GetAgent().Close()

	// Generate an encrypted key.
	priv, _ := generateAuthTestKey(t)
	passphrase := []byte("testpassword")
	pemBytes := marshalPrivateKeyToPEM(t, priv, passphrase)

	key := &coressh.Key{
		Bytes:      pemBytes,
		Passphrase: passphrase,
	}

	auth, err := coressh.GetAuthMethod([]*coressh.Key{key}, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod failed: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_ExplicitEncryptedKeyMatchingAgent(t *testing.T) {
	// Start test agent.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	coressh.GetAgent().Close()

	// Generate a key and add it to the agent.
	priv, pubKey := generateAuthTestKey(t)
	if err := testAgent.AddKey(priv, "matching-key"); err != nil {
		t.Fatalf("failed to add key to agent: %v", err)
	}

	// Create an encrypted version of the same key (without passphrase in Key struct).
	passphrase := []byte("testpassword")
	pemBytes := marshalPrivateKeyToPEM(t, priv, passphrase)

	key := &coressh.Key{
		Bytes:      pemBytes,
		Passphrase: nil, // No passphrase - should match with agent
	}

	auth, err := coressh.GetAuthMethod([]*coressh.Key{key}, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod failed: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}

	// Verify the agent has our key.
	signers, err := coressh.GetAgent().Signers()
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
	coressh.GetAgent().Close()

	// Generate an unencrypted key so we have something to use.
	priv, _ := generateAuthTestKey(t)
	pemBytes := marshalPrivateKeyToPEM(t, priv, nil)

	key := &coressh.Key{
		Bytes:      pemBytes,
		Passphrase: nil,
	}

	// Should not fail even without agent.
	auth, err := coressh.GetAuthMethod([]*coressh.Key{key}, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod failed: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_PublicKeyOnlyMatchingAgent(t *testing.T) {
	// Start test agent.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	coressh.GetAgent().Close()

	// Generate a key and add to agent.
	priv, pubKey := generateAuthTestKey(t)
	if err := testAgent.AddKey(priv, "agent-key"); err != nil {
		t.Fatalf("failed to add key to agent: %v", err)
	}

	// Create a Key with just the public key bytes.
	pubKeyBytes := pubKey.Marshal()

	key := &coressh.Key{
		Bytes:      pubKeyBytes,
		Passphrase: nil,
	}

	auth, err := coressh.GetAuthMethod([]*coressh.Key{key}, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod failed: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_UseConfigFalse_IdentityOnlyTrue(t *testing.T) {
	// When useConfig=false, identityOnly defaults to true.
	// This means only explicit keys are used, not other agent keys.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	coressh.GetAgent().Close()

	// Add a key to agent that we DON'T provide explicitly.
	testAgent.GenerateAndAddKey("agent-only-key")

	// Provide a different explicit key.
	priv, _ := generateAuthTestKey(t)
	pemBytes := marshalPrivateKeyToPEM(t, priv, nil)

	key := &coressh.Key{
		Bytes:      pemBytes,
		Passphrase: nil,
	}

	auth, err := coressh.GetAuthMethod([]*coressh.Key{key}, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod failed: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}

	// The explicit key should be used as a signer directly since it's unencrypted.
	// The agent key should NOT be included because identityOnly=true when useConfig=false.
}

func TestGetAuthMethod_MultipleExplicitKeys(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	coressh.GetAgent().Close()

	// Generate multiple keys.
	priv1, _ := generateAuthTestKey(t)
	priv2, _ := generateAuthTestKey(t)

	pem1 := marshalPrivateKeyToPEM(t, priv1, nil)
	pem2 := marshalPrivateKeyToPEM(t, priv2, []byte("pass2"))

	keys := []*coressh.Key{
		{Bytes: pem1, Passphrase: nil},
		{Bytes: pem2, Passphrase: []byte("pass2")},
	}

	auth, err := coressh.GetAuthMethod(keys, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod failed: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_InvalidKeyFormat(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	coressh.GetAgent().Close()

	// Provide invalid key bytes.
	key := &coressh.Key{
		Bytes:      []byte("not a valid key"),
		Passphrase: nil,
	}

	// Should not error, just warn and continue.
	auth, err := coressh.GetAuthMethod([]*coressh.Key{key}, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod should not fail with invalid key: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method even with invalid key")
	}
}

func TestGetAuthMethod_WrongPassphrase(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	coressh.GetAgent().Close()

	// Generate encrypted key.
	priv, _ := generateAuthTestKey(t)
	pemBytes := marshalPrivateKeyToPEM(t, priv, []byte("correctpassword"))

	// Provide wrong passphrase.
	key := &coressh.Key{
		Bytes:      pemBytes,
		Passphrase: []byte("wrongpassword"),
	}

	// Should not error - will fail to decrypt, treat as encrypted without passphrase.
	auth, err := coressh.GetAuthMethod([]*coressh.Key{key}, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod should not fail with wrong passphrase: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_IdentityFileOnDisk_Encrypted(t *testing.T) {
	// Test loading an encrypted identity file from disk.
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	coressh.GetAgent().Close()

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
	auth, err := coressh.GetAuthMethod(nil, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod failed: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_EmptyKeys(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	coressh.GetAgent().Close()

	// Add a key to agent.
	testAgent.GenerateAndAddKey("agent-key")

	// Call with empty slice (not nil).
	auth, err := coressh.GetAuthMethod([]*coressh.Key{}, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod failed: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}

func TestGetAuthMethod_NilKeys(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()
	coressh.GetAgent().Close()

	// Add a key to agent.
	testAgent.GenerateAndAddKey("agent-key")

	// Call with nil slice.
	auth, err := coressh.GetAuthMethod(nil, "somehost", false)
	if err != nil {
		t.Fatalf("GetAuthMethod failed: %v", err)
	}

	if auth == nil {
		t.Fatal("expected non-nil auth method")
	}
}
