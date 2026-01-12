// Package vault provides Vault container test utilities.
package vault

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	vaultImage       = "hashicorp/vault:1.17"
	vaultRootToken   = "test-root-token"
	vaultWaitRetries = 60
	vaultRetryDelay  = 500 * time.Millisecond
)

// containerNameRegex matches characters not allowed in Docker container names.
var containerNameRegex = regexp.MustCompile(`[^a-zA-Z0-9_.-]`)

// sanitizeContainerName converts a test name to a valid Docker container name.
// Docker container names must match [a-zA-Z0-9][a-zA-Z0-9_.-]*.
func sanitizeContainerName(name string) string {
	// Replace slashes and other invalid chars with hyphens
	sanitized := containerNameRegex.ReplaceAllString(name, "-")
	// Collapse multiple hyphens
	for strings.Contains(sanitized, "--") {
		sanitized = strings.ReplaceAll(sanitized, "--", "-")
	}
	// Trim leading/trailing hyphens
	sanitized = strings.Trim(sanitized, "-")

	return strings.ToLower(sanitized)
}

// Container represents a test container with Vault access.
type Container struct {
	ContainerName string
	Address       string
	Token         string
}

// EnsureVaultContainer starts an ephemeral Vault container in dev mode for testing.
// Returns a configured Container ready for testing.
func EnsureVaultContainer(t *testing.T) *Container {
	t.Helper()

	containerName := "quark-test-vault-" + sanitizeContainerName(t.Name())

	// Remove any stale container with the same name from previous crashed runs
	rmCmd := exec.CommandContext(t.Context(), "docker", "rm", "-f", containerName)
	_ = rmCmd.Run() // Ignore errors - container may not exist

	// Start Vault in dev mode with fixed root token
	startCmd := exec.CommandContext(
		t.Context(),
		"docker",
		"run",
		"-d",
		"--rm",
		"--name",
		containerName,
		"-e", "VAULT_DEV_ROOT_TOKEN_ID="+vaultRootToken,
		"-e", "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		"--cap-add=IPC_LOCK",
		vaultImage,
	)

	output, err := startCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to start vault container: %v\noutput: %s", err, output)
	}

	// Setup cleanup
	t.Cleanup(func() {
		stopCmd := exec.CommandContext(
			t.Context(),
			"docker",
			"stop",
			containerName,
		)
		_ = stopCmd.Run() // Best effort cleanup
	})

	// Get container IP address
	ipCmd := exec.CommandContext(t.Context(),
		"docker", "inspect", "-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
		containerName,
	)

	ipOutput, err := ipCmd.Output()
	if err != nil {
		t.Fatalf("failed to get vault container IP: %v", err)
	}

	containerIP := strings.TrimSpace(string(ipOutput))
	//nolint:nosprintfhostport // Vault dev mode requires http and specific port format
	address := fmt.Sprintf(
		"http://%s:8200", //revive:disable-line:unsecure-url-scheme // Vault dev mode only supports http
		containerIP,
	)

	// Wait for Vault to be healthy
	healthURL := address + "/v1/sys/health"
	vaultReady := false

	httpClient := &http.Client{Timeout: 2 * time.Second} //nolint:mnd // Test code timeout

	for range vaultWaitRetries {
		resp, reqErr := httpClient.Get(healthURL) //nolint:noctx // Test code, context not needed
		if reqErr == nil {
			_ = resp.Body.Close()
			// Vault dev mode returns 200 when ready
			if resp.StatusCode == http.StatusOK {
				vaultReady = true

				break
			}
		}

		time.Sleep(vaultRetryDelay)
	}

	if !vaultReady {
		t.Fatalf("vault never became ready at %s", healthURL)
	}

	return &Container{
		ContainerName: containerName,
		Address:       address,
		Token:         vaultRootToken,
	}
}
