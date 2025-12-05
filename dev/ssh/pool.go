package ssh

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

var errClosingConnections = errors.New("errors closing connections")

// Pool manages SSH connections to multiple hosts.
// It ensures one connection per unique host and reuses connections.
type Pool struct {
	clients map[string]*client
	mu      sync.RWMutex
	log     *slog.Logger
}

// NewPool creates a new SSH connection pool.
func NewPool(log *slog.Logger) *Pool {
	return &Pool{
		clients: make(map[string]*client),
		log:     log,
	}
}

// GetClient returns a Connection for the given endpoint, creating and connecting if needed.
// The endpoint can be an IP address, hostname, or SSH config alias.
// Connection parameters are resolved from ~/.ssh/config.
func (p *Pool) GetClient(endpoint string) (Connection, error) {
	return p.GetClientWithKey(endpoint, "", "")
}

// GetClientWithFingerprint returns a Connection for the given endpoint with optional fingerprint verification.
// If fingerprint is provided, it will be used for host key verification instead of ~/.ssh/known_hosts.
// The fingerprint should be in SHA256 format (e.g., "SHA256:abc123...") or MD5 format (e.g., "MD5:ab:cd:ef...").
func (p *Pool) GetClientWithFingerprint(endpoint, fingerprint string) (Connection, error) {
	return p.GetClientWithKey(endpoint, fingerprint, "")
}

// GetClientWithKey returns a Connection for the given endpoint with optional fingerprint and SSH key.
// If keyContent is provided, it will be used for authentication instead of SSH agent.
// If fingerprint is provided, it will be used for host key verification instead of ~/.ssh/known_hosts.
func (p *Pool) GetClientWithKey(endpoint, fingerprint, keyContent string) (Connection, error) {
	// Use endpoint as key since SSH config will resolve the actual connection params
	key := endpoint

	// Check if client already exists
	p.mu.RLock()
	if client, exists := p.clients[key]; exists {
		p.mu.RUnlock()

		return client, nil
	}
	p.mu.RUnlock()

	// Create new client
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if client, exists := p.clients[key]; exists {
		return client, nil
	}

	p.log.Debug("creating new SSH connection", slog.String("endpoint", key))

	client := newClient(endpoint, fingerprint, keyContent)
	if err := client.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", key, err)
	}

	p.clients[key] = client
	p.log.Info("SSH connection established", slog.String("endpoint", key), slog.String("resolved", client.String()))

	return client, nil
}

// CloseAll closes all SSH connections in the pool.
func (p *Pool) CloseAll() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error

	for key, client := range p.clients {
		p.log.Debug("closing SSH connection", slog.String("host", key))

		if err := client.close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close connection to %s: %w", key, err))
		}
	}

	p.clients = make(map[string]*client)

	if len(errs) > 0 {
		return fmt.Errorf("%w: %v", errClosingConnections, errs)
	}

	return nil
}

// Size returns the number of active connections in the pool.
func (p *Pool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.clients)
}
