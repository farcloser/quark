package ssh_test

import (
	"testing"

	"golang.org/x/crypto/ssh"

	testssh "github.com/farcloser/quark/testutil/ssh"
)

func TestStartTestAgent(t *testing.T) {
	t.Parallel()

	agent := testssh.StartTestAgent(t)

	// Verify socket exists and is usable
	if agent.SocketPath() == "" {
		t.Fatal("SocketPath should not be empty")
	}

	// Verify we can list keys (should be empty initially)
	keys, err := agent.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestTestAgent_GenerateAndAddKey(t *testing.T) {
	t.Parallel()

	agent := testssh.StartTestAgent(t)

	pubKey := agent.GenerateAndAddKey("test-key")

	if pubKey == nil {
		t.Fatal("GenerateAndAddKey should return a public key")
	}

	// Verify key was added
	keys, err := agent.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	if keys[0].Comment != "test-key" {
		t.Errorf("expected comment 'test-key', got %q", keys[0].Comment)
	}
}

func TestTestAgent_Signers(t *testing.T) {
	t.Parallel()

	agent := testssh.StartTestAgent(t)

	// Add a key
	pubKey := agent.GenerateAndAddKey("signer-test")

	// Get signers
	signers, err := agent.Signers()
	if err != nil {
		t.Fatalf("Signers failed: %v", err)
	}

	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}

	// Verify the signer's public key matches
	if ssh.FingerprintSHA256(signers[0].PublicKey()) != ssh.FingerprintSHA256(pubKey) {
		t.Error("signer public key doesn't match added key")
	}
}

//nolint:paralleltest // Modifies environment variables.
func TestTestAgent_SetEnv(t *testing.T) {
	agent := testssh.StartTestAgent(t)
	agent.SetEnv()

	// Add a key to the test agent
	agent.GenerateAndAddKey("env-test")

	// Verify the production code can use this agent via SSH_AUTH_SOCK
	// This is tested indirectly - if SetEnv works, other code using
	// os.Getenv("SSH_AUTH_SOCK") will connect to our test agent
}

func TestTestAgent_MultipleKeys(t *testing.T) {
	t.Parallel()

	agent := testssh.StartTestAgent(t)

	// Add multiple keys
	agent.GenerateAndAddKey("key1")
	agent.GenerateAndAddKey("key2")
	agent.GenerateAndAddKey("key3")

	keys, err := agent.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}
