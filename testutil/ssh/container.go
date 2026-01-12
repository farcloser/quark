// Package ssh provides SSH container test utilities.
package ssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/farcloser/quark/dev/filesystem"
)

const (
	sshWaitRetries   = 30
	sshRetryDelaySec = 1
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

// getTestKeyPath returns the absolute path to the test SSH key.
func getTestKeyPath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		panic("failed to get caller information")
	}

	dir := filepath.Dir(filename)

	return filepath.Join(dir, "test_key")
}

// Container represents a test container with SSH access.
type Container struct {
	ContainerID string
	Endpoint    string
	Host        string
	Port        string
}

// EnsureDebianContainer starts an ephemeral Debian container with SSH enabled.
// Returns a configured Container ready for testing.
func EnsureDebianContainer(t *testing.T) *Container {
	t.Helper()

	// Container configuration - use test name to ensure uniqueness per test
	containerName := "quark-test-" + sanitizeContainerName(t.Name())

	// Remove any stale container with the same name from previous crashed runs
	rmCmd := exec.CommandContext(t.Context(), "docker", "rm", "-f", containerName)
	_ = rmCmd.Run() // Ignore errors - container may not exist

	// Read test SSH public key
	testKeyPath := getTestKeyPath()
	pubKeyPath := testKeyPath + ".pub"

	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("failed to read test SSH public key: %v", err)
	}

	pubKey := string(pubKeyBytes)

	// Start Debian container with SSH server
	// Using debian image, install openssh-server and sudo, inject public key
	startCmd := exec.CommandContext(
		t.Context(),
		"docker",
		"run",
		"-d",
		"--rm",
		"--name",
		containerName,
		"debian:bookworm-slim",
		"sh",
		"-c",
		"apt-get update -qq && "+
			"apt-get install -y -qq openssh-server sudo && "+
			"mkdir -p /run/sshd /root/.ssh && "+
			"chmod 700 /root/.ssh && "+
			"echo '"+pubKey+"' > /root/.ssh/authorized_keys && "+
			"chmod 600 /root/.ssh/authorized_keys && "+
			"/usr/sbin/sshd -D",
	)

	output, err := startCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to start container: %v\noutput: %s", err, output)
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
		t.Fatalf("failed to get container IP: %v", err)
	}

	containerIP := string(ipOutput)
	containerIP = containerIP[:len(containerIP)-1] // Remove trailing newline

	// Wait for SSH port to be open before scanning keys
	sshReady := false

	for range sshWaitRetries {
		ncCmd := exec.CommandContext(
			t.Context(),
			"nc",
			"-z",
			containerIP,
			"22",
		)
		if ncCmd.Run() == nil {
			sshReady = true

			break
		}

		time.Sleep(sshRetryDelaySec * time.Second)
	}

	if !sshReady {
		t.Fatalf("SSH port never became ready on %s:22", containerIP)
	}

	// Ensure ~/.ssh directory exists and scan host keys
	homeDir := filesystem.HomeDir()

	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, filesystem.DirPermissionsPrivate); err != nil {
		t.Fatalf("failed to create .ssh directory: %v", err)
	}

	knownHostsPath := filepath.Join(sshDir, "known_hosts")

	// Scan and add host keys to known_hosts
	keyscanCmd := exec.CommandContext(
		t.Context(),
		"ssh-keyscan",
		"-H",
		containerIP,
	)

	keyscanOutput, err := keyscanCmd.Output()
	if err != nil {
		t.Fatalf("failed to scan host key: %v", err)
	}

	// Append to known_hosts

	knownHostsFile, err := os.OpenFile(
		knownHostsPath,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		filesystem.FilePermissionsPrivate,
	)
	if err != nil {
		t.Fatalf("failed to open known_hosts: %v", err)
	}
	defer knownHostsFile.Close()

	if _, err := knownHostsFile.Write(keyscanOutput); err != nil {
		t.Fatalf("failed to write to known_hosts: %v", err)
	}

	// Cleanup: remove this host from known_hosts when test ends
	t.Cleanup(func() {
		_ = exec.CommandContext(t.Context(), "ssh-keygen", "-R", containerIP).
			Run()
	})

	// Add test key to SSH agent for this session
	// First, ensure the private key has correct permissions (SSH requires 0600)
	if err := os.Chmod(testKeyPath, filesystem.FilePermissionsPrivate); err != nil {
		t.Fatalf("failed to set test key permissions: %v", err)
	}

	addKeyCmd := exec.CommandContext(
		t.Context(),
		"ssh-add",
		testKeyPath,
	)

	addKeyOutput, err := addKeyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to add test key to agent: %v\noutput: %s", err, addKeyOutput)
	}

	// Wait for SSH to be fully ready (authentication working)
	endpoint := "root@" + containerIP
	sshWorking := false

	for range sshWaitRetries {
		// Use ssh command to verify connection works
		sshCmd := exec.CommandContext(
			t.Context(),
			"ssh",
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=5",
			"-o", "StrictHostKeyChecking=no",
			endpoint,
			"echo test",
		)

		if sshCmd.Run() == nil {
			sshWorking = true

			break
		}

		time.Sleep(sshRetryDelaySec * time.Second)
	}

	if !sshWorking {
		t.Fatalf("SSH connection never became ready for %s", endpoint)
	}

	return &Container{
		ContainerID: containerName,
		Endpoint:    endpoint,
		Host:        containerIP,
		Port:        "22",
	}
}
