package secrets

import "errors"

// Generic encryption/decryption errors (apply to encryption-based backends like age, SOPS).
var (
	// ErrNoMatchingIdentity indicates no identity could decrypt the content.
	ErrNoMatchingIdentity = errors.New("no identity matched (wrong key?)")

	// ErrDecryptionFailed indicates decryption operation failed.
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrIdentityNotSet indicates that the provided identity has none...
	ErrIdentityNotSet = errors.New("no identity was found")
)

// 1Password-specific errors.
var (
	// ErrOpGetItem indicates failed to get item from 1Password.
	ErrOpGetItem = errors.New("1password get item failed")

	// ErrOpParseItem indicates failed to parse 1Password item JSON.
	ErrOpParseItem = errors.New("1password parse item failed")

	// ErrOpReadSecret indicates failed to read secret from 1Password.
	ErrOpReadSecret = errors.New("1password read secret failed")
)

// Vault-specific errors.
var (
	// ErrVaultNotConfigured indicates Vault address or token is not configured.
	ErrVaultNotConfigured = errors.New("vault not configured (check VAULT_ADDR and VAULT_TOKEN)")

	// ErrVaultUnavailable indicates Vault server is unreachable.
	ErrVaultUnavailable = errors.New("vault server unavailable")

	// ErrVaultPermissionDenied indicates insufficient permissions for the operation.
	ErrVaultPermissionDenied = errors.New("vault permission denied")

	// ErrVaultSecretNotFound indicates the secret path does not exist.
	ErrVaultSecretNotFound = errors.New("vault secret not found")

	// ErrVaultReadEnv indicates failed to read vault environment.
	ErrVaultReadEnv = errors.New("failed to read vault environment")

	// ErrVaultCreateClient indicates failed to create vault client.
	ErrVaultCreateClient = errors.New("failed to create vault client")

	// ErrVaultMarshal indicates failed to marshal vault data.
	ErrVaultMarshal = errors.New("failed to marshal vault data")

	// ErrVaultOperation indicates a generic vault operation error.
	ErrVaultOperation = errors.New("vault operation failed")
)
