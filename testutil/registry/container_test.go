package registry_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/farcloser/quark/testutil"
	testreg "github.com/farcloser/quark/testutil/registry"
)

func TestEnsureContainerRegistry(t *testing.T) {
	t.Parallel()

	if !testutil.DockerAvailable(t.Context()) {
		t.Skip("Docker not available")
	}

	reg, err := testreg.EnsureContainerRegistry()
	if err != nil {
		t.Fatalf("EnsureContainerRegistry failed: %v", err)
	}

	if reg.Address == "" {
		t.Fatal("Address should not be empty")
	}

	// Verify registry is reachable
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+reg.Address+"/v2/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("registry not reachable at %s: %v", reg.Address, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}
