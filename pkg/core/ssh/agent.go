package ssh

import (
	"fmt"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

//nolint:gochecknoglobals
var (
	agt         *Agent
	agentCreate sync.Once
)

// GetAgent returns an agent.
func GetAgent() *Agent {
	agentCreate.Do(func() {
		agt = &Agent{}
	})

	return agt
}

// Agent represents a local SSH agent, allowing to access signers.
type Agent struct {
	conn   net.Conn
	client agent.ExtendedAgent
	mu     sync.Mutex
}

// Signers returns all agent's signers.
func (sag *Agent) Signers() ([]ssh.Signer, error) {
	sag.mu.Lock()
	defer sag.mu.Unlock()

	if err := sag.ensureConnection(); err != nil {
		return nil, err
	}

	signers, err := sag.client.Signers()
	if err != nil {
		err = fmt.Errorf("%w: %w", ErrAgentGetSignersFailed, err)
	}

	return signers, err
}

// Close terminates the connection to the agent and cleanup.
func (sag *Agent) Close() {
	sag.mu.Lock()
	defer sag.mu.Unlock()

	if sag.conn != nil {
		sag.clean()
	}
}

func (sag *Agent) clean() {
	_ = sag.conn.Close()
	sag.conn = nil
	sag.client = nil
}

// ensureConnection establishes connection to SSH agent. Caller must hold mutex.
func (sag *Agent) ensureConnection() error {
	if sag.conn != nil {
		// Test if alive
		if _, err := sag.client.List(); err == nil {
			return nil
		}

		sag.clean()
	}

	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return fmt.Errorf("%w: no known socket", ErrAgentFailedToConnect)
	}

	conn, err := net.Dial("unix", socket) //nolint:noctx // Unix socket - local IPC, not network
	if err != nil {
		return fmt.Errorf("%w: failed to dial socket: %w", ErrAgentFailedToConnect, err)
	}

	sag.conn = conn
	sag.client = agent.NewClient(sag.conn)

	// Test if alive
	if _, err = sag.client.List(); err != nil {
		sag.clean()

		return fmt.Errorf("%w: agent unresponsive: %w", ErrAgentFailedToConnect, err)
	}

	return nil
}
