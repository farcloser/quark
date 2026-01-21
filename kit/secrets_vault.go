package kit

import (
	intsecrets "github.com/farcloser/quark/internal/secrets"
	devsecrets "github.com/farcloser/quark/pkg/dev/secrets"
)

// VaultBackendConfig provides optional configuration overrides for VaultBackend.
// All fields are optional - if empty, environment variables are used instead.
type VaultBackendConfig struct {
	// Address overrides VAULT_ADDR environment variable.
	Address string
	// Token overrides VAULT_TOKEN environment variable.
	Token string
	// Namespace overrides VAULT_NAMESPACE environment variable.
	Namespace string
}

// AddVaultBackend creates a new Vault backend with optional configuration overrides.
// If config is nil, uses VAULT_ADDR, VAULT_TOKEN, and VAULT_NAMESPACE environment variables.
func AddVaultBackend(config *VaultBackendConfig) {
	backend := &intsecrets.VaultBackend{}

	if config != nil {
		backend.Address = config.Address
		backend.Token = config.Token
		backend.Namespace = config.Namespace
	}

	devsecrets.GetResolver().Register(backend)
}
