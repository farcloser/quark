package git

import (
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/farcloser/quark/pkg/core/sshprime"
)

// SSHAuth implements transport.AuthMethod using hardened SSH settings.
// Wraps pkg/core/ssh to provide:
//   - Modern key exchanges (Curve25519 only)
//   - AEAD ciphers only (ChaCha20-Poly1305, AES-GCM)
//   - Encrypt-then-MAC only
//   - Ed25519 host keys only
//   - ~/.ssh/config resolution (User, Hostname, Port, IdentityFile)
//   - Explicit key or SSH agent authentication (with IdentitiesOnly filtering)
//   - Fingerprint or known_hosts verification
type SSHAuth struct {
	endpoint      string
	fingerprint   string
	key           sshprime.Key
	withSSHConfig bool
}

// NewSSHAuth creates an SSH auth method with hardened settings and wired key management.
//
// Parameters:
//   - endpoint: SSH host (can be ~/.ssh/config alias, hostname, or user@host)
//   - fingerprint: Optional SHA256 fingerprint for host key verification (overrides known_hosts)
//   - key: Optional SSH key for authentication
//
// If fingerprint is empty, ~/.ssh/known_hosts is used for host verification.
func NewSSHAuth(endpoint, fingerprint string, key sshprime.Key, withSSHConfig bool) *SSHAuth {
	return &SSHAuth{
		endpoint:      endpoint,
		fingerprint:   fingerprint,
		key:           key,
		withSSHConfig: withSSHConfig,
	}
}

// Name returns the name of this auth method.
func (*SSHAuth) Name() string {
	return "ssh-hardened"
}

// String returns a string representation of the auth method.
func (a *SSHAuth) String() string {
	return a.endpoint
}

// ClientConfig returns the SSH client configuration.
// This is called by go-git when establishing SSH connections.
func (a *SSHAuth) ClientConfig() (*ssh.ClientConfig, error) {
	// Resolve the endpoint
	endpoint, err := sshprime.Resolve(a.endpoint, a.withSSHConfig)
	if err != nil {
		return nil, fmt.Errorf("resolve endpoint: %w", err)
	}

	// If fingerprint is provided, trust it before getting the config
	if a.fingerprint != "" {
		sshprime.GetFingerprinter().Trust(endpoint, a.fingerprint)
	}

	// Build keys slice if key is provided
	var keys []sshprime.Key
	if a.key != nil {
		keys = []sshprime.Key{a.key}
	}

	cfg, err := sshprime.GetClientConfig(keys, endpoint, a.withSSHConfig)
	if err != nil {
		return nil, fmt.Errorf("get ssh config: %w", err)
	}

	return cfg, nil
}
