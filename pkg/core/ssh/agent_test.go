package ssh_test

import (
	"errors"
	"testing"

	"github.com/farcloser/quark/pkg/core/ssh"
	testssh "github.com/farcloser/quark/testutil/ssh"
)

func TestGetAgent_Singleton(t *testing.T) {
	t.Parallel()

	agent1 := ssh.GetAgent()
	agent2 := ssh.GetAgent()

	if agent1 != agent2 {
		t.Error("GetAgent should return the same instance")
	}
}

//nolint:paralleltest // t.Setenv cannot be used with t.Parallel.
func TestAgent_Signers_WithTestAgent(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()

	// Add a key to the test agent
	testAgent.GenerateAndAddKey("test-key")

	// Get the production Agent and test Signers
	agent := ssh.GetAgent()

	// Close any existing connection so it reconnects to our test agent
	agent.Close()

	signers, err := agent.Signers()
	if err != nil {
		t.Fatalf("Signers failed: %v", err)
	}

	if len(signers) != 1 {
		t.Errorf("expected 1 signer, got %d", len(signers))
	}
}

func TestAgent_Signers_NoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")

	agent := ssh.GetAgent()
	agent.Close() // Force reconnection attempt

	_, err := agent.Signers()
	if err == nil {
		t.Fatal("Signers should fail when no agent available")
	}
}

func TestAgent_Signers_InvalidSocket(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/nonexistent/socket.sock")

	agent := ssh.GetAgent()
	agent.Close() // Force reconnection attempt

	_, err := agent.Signers()
	if err == nil {
		t.Fatal("Signers should fail with invalid socket")
	}

	if !errors.Is(err, ssh.ErrAgentFailedToConnect) {
		t.Errorf("expected ErrAgentFailedToConnect, got: %v", err)
	}
}

//nolint:paralleltest // t.Setenv cannot be used with t.Parallel.
func TestAgent_Close(t *testing.T) {
	testAgent := testssh.StartTestAgent(t)
	testAgent.SetEnv()

	agent := ssh.GetAgent()
	agent.Close() // Force fresh connection

	// First call should work
	_, err := agent.Signers()
	if err != nil {
		t.Fatalf("first Signers call failed: %v", err)
	}

	// Close the agent
	agent.Close()

	// Next call should reconnect and work
	_, err = agent.Signers()
	if err != nil {
		t.Fatalf("Signers after Close failed: %v", err)
	}
}
