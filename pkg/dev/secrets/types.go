package secrets

import "context"

// Backend defines the interface for secret resolution backends.
type Backend interface {
	// Resolve retrieves secrets from the backend.
	// path: Backend-specific path without scheme (e.g., "vault/item" or "path/to/file.age/key")
	// fields: List of field names to extract from the secret
	// Returns a map of field name to field value.
	Resolve(ctx context.Context, path string, fields []string) (map[string]string, error)

	// ResolveDocument retrieves raw document content from the backend.
	// path: Backend-specific path without scheme (e.g., "vault/item" or "path/to/file.age")
	// Returns the raw decrypted/retrieved content as bytes.
	ResolveDocument(ctx context.Context, path string) ([]byte, error)

	// Scheme returns the URI scheme this backend handles (e.g., "op", "age")
	Scheme() string
}
