package secrets

import (
	"context"
	"fmt"

	"filippo.io/age"
	"github.com/farcloser/quark/pkg/dev/secrets"
	"github.com/farcloser/quark/pkg/fault"
)

// VaultConfig configures the Vault backend.
// Address, Token, and Namespace can be left empty to use environment variables
// (VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE).
type VaultConfig struct {
	Address   string
	Token     string
	Namespace string
}

// CreateBackend creates a Vault backend with the provided configuration.
func (c *VaultConfig) CreateBackend(_ context.Context) (secrets.Backend, error) {
	return &VaultBackend{
		Address:   c.Address,
		Token:     c.Token,
		Namespace: c.Namespace,
	}, nil
}

// AgeConfig configures the Age backend with a decryption identity.
// Identity is the raw age secret key string (AGE-SECRET-KEY-1...).
type AgeConfig struct {
	Identity string
}

// CreateBackend parses the identity and creates the Age backend.
func (c *AgeConfig) CreateBackend(_ context.Context) (secrets.Backend, error) {
	identity, err := age.ParseX25519Identity(c.Identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrInvalidArgument, err)
	}

	return &AgeBackend{
		identities: []age.Identity{identity},
	}, nil
}

// AgeConfigMulti configures the Age backend with multiple decryption identities.
// Useful when you need to try multiple keys.
type AgeConfigMulti struct {
	Identities []string
}

// CreateBackend parses all identities and creates the Age backend.
func (c *AgeConfigMulti) CreateBackend(_ context.Context) (secrets.Backend, error) {
	identities := make([]age.Identity, 0, len(c.Identities))

	for _, raw := range c.Identities {
		identity, err := age.ParseX25519Identity(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", fault.ErrInvalidArgument, err)
		}

		identities = append(identities, identity)
	}

	return &AgeBackend{
		identities: identities,
	}, nil
}

// OnePasswordConfig configures the 1Password backend.
// 1Password uses CLI-based authentication, so no config fields are needed here.
// CreateBackend will trigger authentication (biometrics/service account).
type OnePasswordConfig struct{}

// CreateBackend creates the 1Password backend and triggers authentication.
func (c *OnePasswordConfig) CreateBackend(ctx context.Context) (secrets.Backend, error) {
	backend := &OnePasswordBackend{}

	// Trigger authentication (biometrics prompt or service account)
	if err := backend.Authenticate(ctx); err != nil {
		return nil, err
	}

	return backend, nil
}
