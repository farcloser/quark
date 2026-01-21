package kit

import (
	"context"
	"fmt"

	secrets2 "github.com/farcloser/quark/pkg/dev/secrets"
	"github.com/farcloser/quark/pkg/fault"
)

// AddSecretsBackend configures and registers a secrets backend.
// Each config type knows how to create its corresponding backend and
// trigger any required authentication (e.g., 1Password biometrics).
//
// Examples:
//
//	// Configure 1Password backend (triggers biometric auth)
//	if err := kit.AddSecretsBackend(ctx, secrets.OnePasswordConfig{}); err != nil {
//	    return err
//	}
//
//	// Configure Vault backend with explicit config
//	if err := kit.AddSecretsBackend(ctx, secrets.VaultConfig{
//	    Address: "https://vault.example.com",
//	    Token:   vaultToken,
//	}); err != nil {
//	    return err
//	}
//
//	// Configure Age backend - identity can come from anywhere (e.g., 1Password)
//	ageKey, _ := kit.GetSecret(ctx, "op://vault/age-key", []string{"identity"})
//	if err := kit.AddSecretsBackend(ctx, secrets.AgeConfig{
//	    Identity: ageKey["identity"],
//	}); err != nil {
//	    return err
//	}
func AddSecretsBackend(ctx context.Context, config secrets2.BackendConfig) error {
	backend, err := config.CreateBackend(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", fault.ErrAuthenticationFailure, err)
	}

	secrets2.GetResolver().Register(backend)

	return nil
}

// GetSecretDocument retrieves raw document content using the global resolver.
// Supports multiple URI schemes:
//   - "op://vault/item" - 1Password document
//   - "age://path/to/file.age" - age encrypted file (raw decrypted content)
//   - "vault://mount/path" - HashiCorp Vault KV v2 secret (as JSON)
//
// Examples:
//
//	// 1Password document
//	content, err := GetSecretDocument(ctx, "op://Security (office)/scimsession file")
//
//	// Age encrypted SSH key
//	sshKey, err := GetSecretDocument(ctx, "age://secrets/deploy-key.age")
//
//	// Vault KV v2 secret (returns JSON)
//	secretJSON, err := GetSecretDocument(ctx, "vault://secret/myapp/db")
//
// Returns the raw document content as bytes (no JSON parsing for age/op, JSON for vault).
func GetSecretDocument(ctx context.Context, uri string) ([]byte, error) {
	data, err := secrets2.GetResolver().ResolveDocument(ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSecretsReadFailed, err)
	}

	return data, nil
}

// GetSecret retrieves specific fields from a secret identified by URI.
// Supports multiple URI schemes:
//   - "op://vault/item" - 1Password
//   - "age://path/to/file.age[/json/path]" - age encryption
//   - "vault://mount/path" - HashiCorp Vault KV v2
//
// Examples:
//
//	// 1Password
//	secrets, err := Get(ctx, "op://Security (build)/deploy.registry.rw",
//	    []string{"organization", "username", "password"})
//
//	// Age encryption
//	secrets, err := Get(ctx, "age://secrets/db.json.age/prod",
//	    []string{"host", "password"})
//
//	// Vault KV v2 (uses VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE env vars)
//	secrets, err := Get(ctx, "vault://secret/myapp/db",
//	    []string{"username", "password"})
//
// Returns a map of field names to their string values.
func GetSecret(ctx context.Context, uri string, fields []string) (map[string]string, error) {
	result, err := secrets2.GetResolver().Resolve(ctx, uri, fields)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSecretsReadFailed, err)
	}

	return result, nil
}
