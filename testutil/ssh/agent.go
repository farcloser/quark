package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const sshAuthSockEnv = "SSH_AUTH_SOCK"

// TestAgent is a test helper that runs an in-process SSH agent.
type TestAgent struct {
	t        *testing.T
	keyring  agent.Agent
	listener net.Listener
	sockPath string
	done     chan struct{}
}

// StartTestAgent starts a new in-process SSH agent for testing.
// The agent listens on a Unix socket in a temp directory.
// Call Stop() or use t.Cleanup to shut it down.
func StartTestAgent(t *testing.T) *TestAgent {
	t.Helper()

	// Use os.MkdirTemp with short prefix instead of t.TempDir() because
	// t.TempDir() includes the test name which can exceed Unix socket path limits (~104 bytes on macOS).
	tmpDir, err := os.MkdirTemp("", "ssh")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}

	sockPath := filepath.Join(tmpDir, "a.s")

	listenConfig := &net.ListenConfig{}

	listener, err := listenConfig.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("failed to create agent socket: %v", err)
	}

	keyring := agent.NewKeyring()
	testAgent := &TestAgent{
		t:        t,
		keyring:  keyring,
		listener: listener,
		sockPath: sockPath,
		done:     make(chan struct{}),
	}

	go testAgent.serve()

	t.Cleanup(func() {
		testAgent.Stop()
		_ = os.RemoveAll(tmpDir)
	})

	return testAgent
}

// Stop shuts down the test agent.
func (ta *TestAgent) Stop() {
	close(ta.done)
	_ = ta.listener.Close()
}

// SocketPath returns the path to the agent's Unix socket.
// Use this to set SSH_AUTH_SOCK in tests.
func (ta *TestAgent) SocketPath() string {
	return ta.sockPath
}

// SetEnv sets SSH_AUTH_SOCK to point to this test agent.
// Uses t.Setenv so it automatically restores on test cleanup.
func (ta *TestAgent) SetEnv() {
	ta.t.Setenv(sshAuthSockEnv, ta.sockPath)
}

// AddKey adds an existing private key to the agent.
func (ta *TestAgent) AddKey(privateKey any, comment string) error {
	err := ta.keyring.Add(agent.AddedKey{
		PrivateKey: privateKey,
		Comment:    comment,
	})
	if err != nil {
		return fmt.Errorf("adding key to agent: %w", err)
	}

	return nil
}

// GenerateAndAddKey generates a new ed25519 key, adds it to the agent,
// and returns the public key.
func (ta *TestAgent) GenerateAndAddKey(comment string) ssh.PublicKey {
	ta.t.Helper()

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		ta.t.Fatalf("failed to generate key: %v", err)
	}

	err = ta.keyring.Add(agent.AddedKey{
		PrivateKey: privKey,
		Comment:    comment,
	})
	if err != nil {
		ta.t.Fatalf("failed to add key to agent: %v", err)
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		ta.t.Fatalf("failed to convert public key: %v", err)
	}

	return sshPubKey
}

// ListKeys returns the public keys currently in the agent.
func (ta *TestAgent) ListKeys() ([]*agent.Key, error) {
	keys, err := ta.keyring.List()
	if err != nil {
		return nil, fmt.Errorf("listing agent keys: %w", err)
	}

	return keys, nil
}

// Client returns an agent client connected to this test agent.
func (ta *TestAgent) Client() agent.ExtendedAgent {
	dialer := &net.Dialer{}

	conn, err := dialer.DialContext(context.Background(), "unix", ta.sockPath)
	if err != nil {
		ta.t.Fatalf("failed to connect to test agent: %v", err)
	}

	ta.t.Cleanup(func() {
		_ = conn.Close()
	})

	return agent.NewClient(conn)
}

// Signers returns the signers from this test agent.
func (ta *TestAgent) Signers() ([]ssh.Signer, error) {
	signers, err := ta.Client().Signers()
	if err != nil {
		return nil, fmt.Errorf("getting agent signers: %w", err)
	}

	return signers, nil
}

// WithOriginalAgent temporarily restores the original SSH_AUTH_SOCK
// and runs the provided function.
func WithOriginalAgent(t *testing.T, callback func()) {
	t.Helper()

	originalSock := os.Getenv(sshAuthSockEnv)
	if originalSock == "" {
		t.Skip("no original SSH_AUTH_SOCK set")
	}

	// Restore original for the duration of callback
	current := os.Getenv(sshAuthSockEnv)

	t.Setenv(sshAuthSockEnv, originalSock)
	callback()
	t.Setenv(sshAuthSockEnv, current)
}

// serve accepts connections and handles agent requests.
func (ta *TestAgent) serve() {
	for {
		conn, err := ta.listener.Accept()
		if err != nil {
			select {
			case <-ta.done:
				return
			default:
				continue
			}
		}

		go func(c net.Conn) {
			defer c.Close()

			_ = agent.ServeAgent(ta.keyring, c)
		}(conn)
	}
}
