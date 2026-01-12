package vault_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/farcloser/quark/testutil"
	testvault "github.com/farcloser/quark/testutil/vault"
)

//nolint:paralleltest // Container tests modify shared Docker state.
func TestEnsureVaultContainer(t *testing.T) {
	if !testutil.DockerAvailable(t.Context()) {
		t.Skip("Docker not available")
	}

	container := testvault.EnsureVaultContainer(t)

	if container.ContainerName == "" {
		t.Fatal("ContainerName should not be empty")
	}

	if container.Address == "" {
		t.Fatal("Address should not be empty")
	}

	if container.Token == "" {
		t.Fatal("Token should not be empty")
	}

	// Verify Vault API is reachable
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, container.Address+"/v1/sys/health", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Vault not reachable at %s: %v", container.Address, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}
