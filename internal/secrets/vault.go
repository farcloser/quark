package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/dev/secrets"
)

// VaultBackend implements secret resolution using HashiCorp Vault KV v2.
// Supports token authentication with VAULT_ADDR, VAULT_TOKEN, and VAULT_NAMESPACE
// environment variables, which can be overridden via VaultConfig.
type VaultBackend struct {
	Address   string
	Token     string
	Namespace string
}

// Scheme returns the URI scheme for Vault ("vault").
func (*VaultBackend) Scheme() string {
	return "vault"
}

// Resolve retrieves secrets from Vault KV v2.
// Path format: "mount/path/to/secret"
// Example: "secret/myapp/db" -> mount="secret", path="myapp/db"
// Fields: list of field names to extract from the secret data.
func (v *VaultBackend) Resolve(ctx context.Context, path string, fields []string) (map[string]string, error) {
	if path == "" {
		return nil, fault.ErrInvalidArgument
	}

	if len(fields) == 0 {
		return nil, fault.ErrNotFound
	}

	mount, secretPath, err := v.parsePath(path)
	if err != nil {
		return nil, err
	}

	client, err := v.createClient()
	if err != nil {
		return nil, err
	}

	secret, err := client.KVv2(mount).Get(ctx, secretPath)
	if err != nil {
		return nil, v.wrapError(err, path)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: %q", ErrVaultSecretNotFound, path)
	}

	return v.extractFields(secret.Data, fields)
}

// ResolveDocument retrieves raw secret data from Vault KV v2 as JSON.
// Path format: "mount/path/to/secret"
// Returns the secret data marshaled as JSON bytes.
func (v *VaultBackend) ResolveDocument(ctx context.Context, path string) ([]byte, error) {
	if path == "" {
		return nil, fault.ErrInvalidArgument
	}

	mount, secretPath, err := v.parsePath(path)
	if err != nil {
		return nil, err
	}

	client, err := v.createClient()
	if err != nil {
		return nil, err
	}

	secret, err := client.KVv2(mount).Get(ctx, secretPath)
	if err != nil {
		return nil, v.wrapError(err, path)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: %q", ErrVaultSecretNotFound, path)
	}

	data, err := json.Marshal(secret.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVaultMarshal, err)
	}

	if len(data) == 0 {
		return nil, secrets.ErrDocumentEmpty
	}

	return data, nil
}

// parsePath splits "mount/path/to/secret" into mount and secret path.
// Example: "secret/myapp/db" -> ("secret", "myapp/db").
func (*VaultBackend) parsePath(path string) (mount, secretPath string, err error) {
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("%w (expected 'mount/path'): %q", fault.ErrInvalidArgument, path)
	}

	mount = parts[0]
	secretPath = parts[1]

	if mount == "" || secretPath == "" {
		return "", "", fmt.Errorf("%w: %q", fault.ErrInvalidArgument, path)
	}

	return mount, secretPath, nil
}

// createClient creates a configured Vault API client.
// Honors VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE environment variables,
// with overrides from VaultConfig taking precedence.
func (v *VaultBackend) createClient() (*api.Client, error) {
	config := api.DefaultConfig()

	// ReadEnvironment reads VAULT_ADDR, VAULT_CACERT, VAULT_CAPATH,
	// VAULT_CLIENT_CERT, VAULT_CLIENT_KEY, VAULT_SKIP_VERIFY, etc.
	if err := config.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVaultReadEnv, err)
	}

	// Apply address override if set
	if v.Address != "" {
		config.Address = v.Address
	}

	// Validate we have an address
	if config.Address == "" {
		return nil, ErrVaultNotConfigured
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVaultCreateClient, err)
	}

	// Apply token: override takes precedence, otherwise use client's token
	// (which was set from VAULT_TOKEN by ReadEnvironment via the client constructor)
	if v.Token != "" {
		client.SetToken(v.Token)
	}

	// Validate we have a token
	if client.Token() == "" {
		return nil, ErrVaultNotConfigured
	}

	// Apply namespace: override takes precedence, otherwise use VAULT_NAMESPACE
	// (already read by the client)
	if v.Namespace != "" {
		client.SetNamespace(v.Namespace)
	}

	return client, nil
}

// extractFields extracts requested fields from Vault secret data.
func (*VaultBackend) extractFields(data map[string]any, fields []string) (map[string]string, error) {
	result := make(map[string]string)

	for _, fieldName := range fields {
		value, found := data[fieldName]
		if !found {
			return nil, fmt.Errorf("%w: %q", fault.ErrNotFound, fieldName)
		}

		var strValue string

		switch typedValue := value.(type) {
		case string:
			strValue = typedValue
		case map[string]any, []any:
			jsonBytes, err := json.Marshal(typedValue)
			if err != nil {
				return nil, fmt.Errorf("%w %q: %w", fault.ErrInvalidJSON, fieldName, err)
			}

			strValue = string(jsonBytes)
		default:
			strValue = fmt.Sprint(typedValue)
		}

		result[fieldName] = strValue
	}

	return result, nil
}

// wrapError converts Vault API errors to appropriate sentinel errors.
func (*VaultBackend) wrapError(err error, path string) error {
	errStr := err.Error()

	// Check for permission denied (403)
	if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "403") {
		return fmt.Errorf("%w: %s", ErrVaultPermissionDenied, path)
	}

	// Check for not found (404)
	if strings.Contains(errStr, "secret not found") || strings.Contains(errStr, "404") {
		return fmt.Errorf("%w: %q", ErrVaultSecretNotFound, path)
	}

	// Check for connection errors
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "dial tcp") {
		return fmt.Errorf("%w: %w", ErrVaultUnavailable, err)
	}

	// Generic vault error
	return fmt.Errorf("%w for %q: %w", ErrVaultOperation, path, err)
}
