package registry_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	testreg "github.com/farcloser/quark/testutil/registry"
)

func TestEnsureInMemoryRegistry(t *testing.T) {
	t.Parallel()

	reg := testreg.EnsureInMemoryRegistry(t)

	if reg.Address == "" {
		t.Fatal("Address should not be empty")
	}

	// Verify address format (host:port)
	if !strings.Contains(reg.Address, ":") {
		t.Errorf("Address should contain port separator, got %q", reg.Address)
	}
}

func TestInMemoryRegistry_URL(t *testing.T) {
	t.Parallel()

	reg := testreg.EnsureInMemoryRegistry(t)

	url := reg.URL()
	if url == "" {
		t.Fatal("URL should not be empty")
	}

	if !strings.HasPrefix(url, "http://") {
		t.Errorf("URL should start with http://, got %q", url)
	}

	// URL should contain address
	if !strings.Contains(url, reg.Address) {
		t.Errorf("URL %q should contain address %q", url, reg.Address)
	}
}

func TestInMemoryRegistry_IsAccessible(t *testing.T) {
	t.Parallel()

	reg := testreg.EnsureInMemoryRegistry(t)

	// OCI registries respond to /v2/ with 200 OK
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, reg.URL()+"/v2/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to connect to registry: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestInMemoryRegistry_MultipleInstances(t *testing.T) {
	t.Parallel()

	reg1 := testreg.EnsureInMemoryRegistry(t)
	reg2 := testreg.EnsureInMemoryRegistry(t)

	// Each call should create a separate instance with different addresses
	if reg1.Address == reg2.Address {
		t.Error("multiple registries should have different addresses")
	}
}
