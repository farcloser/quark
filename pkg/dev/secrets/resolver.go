package secrets

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/farcloser/quark/pkg/fault"
)

// Resolver manages secret backends and routes requests to the appropriate backend.
type Resolver struct {
	backends map[string]Backend

	mu sync.Mutex
}

// Register registers a backend for a specific URI scheme.
func (r *Resolver) Register(backend Backend) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.backends == nil {
		r.backends = make(map[string]Backend)
	}

	r.backends[backend.Scheme()] = backend
}

// Resolve routes a secret resolution request to the appropriate backend.
// URI format: "scheme://path"
// Returns a map of field names to values.
func (r *Resolver) Resolve(ctx context.Context, uri string, fields []string) (map[string]string, error) {
	// Extract scheme and path from URI
	scheme, path := extractSchemeAndPath(uri)
	if scheme == "" {
		return nil, fmt.Errorf("%w: no scheme in URI %q", fault.ErrInvalidArgument, uri)
	}

	// Find backend for scheme
	r.mu.Lock()
	backend, found := r.backends[scheme]
	r.mu.Unlock()

	if !found {
		return nil, fmt.Errorf("%w: %q", fault.ErrInvalidArgument, scheme)
	}

	// Delegate to backend with path only
	//nolint:wrapcheck
	return backend.Resolve(ctx, path, fields)
}

// ResolveDocument routes a document resolution request to the appropriate backend.
// URI format: "scheme://path"
// Returns the raw document content as bytes.
func (r *Resolver) ResolveDocument(ctx context.Context, uri string) ([]byte, error) {
	// Extract scheme and path from URI
	scheme, path := extractSchemeAndPath(uri)
	if scheme == "" {
		return nil, fmt.Errorf("%w: no scheme in URI %q", fault.ErrInvalidArgument, uri)
	}

	// Find backend for scheme
	r.mu.Lock()
	backend, found := r.backends[scheme]
	r.mu.Unlock()

	if !found {
		return nil, fmt.Errorf("%w: %q", fault.ErrInvalidArgument, scheme)
	}

	// Delegate to backend with path only
	//nolint:wrapcheck
	return backend.ResolveDocument(ctx, path)
}

// Example: "op://vault/item" -> ("op", "vault/item").
func extractSchemeAndPath(uri string) (scheme, path string) {
	idx := strings.Index(uri, "://")
	if idx == -1 {
		return "", ""
	}

	return uri[:idx], uri[idx+3:]
}
