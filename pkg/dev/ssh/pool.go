package ssh

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/farcloser/quark/pkg/core/network"
	"github.com/farcloser/quark/pkg/core/sshprime"
)

//nolint:gochecknoglobals
var (
	pool       *Pool
	poolCreate sync.Once
)

// GetPool returns the connection pool singleton.
func GetPool() *Pool {
	poolCreate.Do(func() {
		pool = &Pool{
			clients:       make(map[string]*client),
			WithSSHConfig: true,
		}
	})

	return pool
}

// Pool manages SSH connections to multiple hosts.
// It ensures one connection per unique host and reuses connections.
type Pool struct {
	clients       map[string]*client
	mu            sync.RWMutex
	WithSSHConfig bool
}

// GetClientWithKey returns a Connection for the given endpoint with optional fingerprint and SSH key.
// If key is provided, it will be used for authentication additionally to SSH agent (* dependent on ssh configuration
// obviously).
// If fingerprint is provided, it will be used for host key verification in addition to ~/.ssh/known_hosts.
// Connections are health-checked before being returned; dead connections are automatically replaced.
func (p *Pool) GetClientWithKey(endpoint, fingerprint string, sshKey []*sshprime.Key) (Connection, error) {
	// Resolve endpoint
	edp, err := sshprime.Resolve(endpoint, p.WithSSHConfig)
	if err != nil {
		//nolint:wrapcheck
		return nil, err
	}

	endpoint = fmt.Sprintf("%s:%d", edp.Host, edp.Port)

	// Fast path: check if alive client exists (read lock only)
	p.mu.RLock()
	cli, exists := p.clients[endpoint]
	p.mu.RUnlock()

	if exists && cli.IsAlive(network.DefaultSSHKeepaliveTimeout) {
		return cli, nil
	}

	// Slow path: need to create or replace connection
	p.mu.Lock()
	defer p.mu.Unlock()

	// Re-check under write lock (another goroutine may have created/replaced)
	if cli, exists = p.clients[endpoint]; exists {
		if cli.IsAlive(network.DefaultSSHKeepaliveTimeout) {
			return cli, nil
		}

		// Dead connection, close and remove
		slog.Debug("SSH connection dead, reconnecting", slog.String("endpoint", endpoint))

		_ = cli.close()

		delete(p.clients, endpoint)
	}

	slog.Debug("creating new SSH connection", slog.String("endpoint", endpoint))

	// Trust fingerprint
	sshprime.GetFingerprinter().Trust(edp, fingerprint)

	// Get config
	config, err := sshprime.GetClientConfig(sshKey, edp, p.WithSSHConfig)
	if err != nil {
		//nolint:wrapcheck
		return nil, err
	}

	cli = newClient(edp)
	if err = cli.connect(config); err != nil {
		return nil, fmt.Errorf("%w (node: %s)", err, endpoint)
	}

	p.clients[endpoint] = cli
	slog.Debug("SSH connection established", slog.String("endpoint", endpoint))

	return cli, nil
}

// CloseAll closes all SSH connections in the pool.
func (p *Pool) CloseAll() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error

	for key, cli := range p.clients {
		slog.Debug("closing SSH connection", slog.String("host", key))

		if err := cli.close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close connection to %s: %w", key, err))
		}
	}

	p.clients = make(map[string]*client)

	if len(errs) > 0 {
		return fmt.Errorf("%w: %v", ErrClosingConnections, errs)
	}

	return nil
}

// Size returns the number of established connections.
func (p *Pool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.clients)
}
