package secrets

import "context"

// BackendConfig defines the interface for backend configuration types.
// Each config type knows how to create its corresponding backend.
type BackendConfig interface {
	// CreateBackend creates and returns a configured, authenticated backend.
	// For backends requiring authentication (like 1Password), this triggers auth.
	CreateBackend(ctx context.Context) (Backend, error)
}
