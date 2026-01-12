package registry

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
)

// InMemoryRegistry represents an in-memory OCI registry for testing.
// It uses go-containerregistry's in-memory registry implementation
// wrapped in an httptest server.
type InMemoryRegistry struct {
	// Address is the registry address (e.g., "127.0.0.1:12345").
	Address string
	server  *httptest.Server
}

// EnsureInMemoryRegistry creates a new in-memory OCI registry for testing.
// The registry is automatically cleaned up when the test completes.
// Each call creates a new isolated registry instance.
func EnsureInMemoryRegistry(t *testing.T) *InMemoryRegistry {
	t.Helper()

	handler := registry.New()
	server := httptest.NewServer(handler)

	t.Cleanup(func() {
		server.Close()
	})

	// Extract host:port from server URL (remove http:// prefix).
	address := strings.TrimPrefix(server.URL, "http://")

	return &InMemoryRegistry{
		Address: address,
		server:  server,
	}
}

// Close stops the in-memory registry server.
// This is called automatically via t.Cleanup() but can be called manually if needed.
func (r *InMemoryRegistry) Close() {
	if r.server != nil {
		r.server.Close()
	}
}

// URL returns the full HTTP URL of the registry (e.g., "http://127.0.0.1:12345").
func (r *InMemoryRegistry) URL() string {
	if r.server != nil {
		return r.server.URL
	}

	return ""
}
