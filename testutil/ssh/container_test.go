package ssh_test

import (
	"os/exec"
	"testing"

	"github.com/farcloser/quark/testutil"
	testssh "github.com/farcloser/quark/testutil/ssh"
)

//nolint:paralleltest // Container tests modify shared Docker state.
func TestEnsureDebianContainer(t *testing.T) {
	if !testutil.DockerAvailable(t.Context()) {
		t.Skip("Docker not available")
	}

	container := testssh.EnsureDebianContainer(t)

	if container.ContainerID == "" {
		t.Fatal("ContainerID should not be empty")
	}

	if container.Endpoint == "" {
		t.Fatal("Endpoint should not be empty")
	}

	if container.Host == "" {
		t.Fatal("Host should not be empty")
	}

	if container.Port != "22" {
		t.Errorf("expected Port '22', got %q", container.Port)
	}

	// Verify SSH connection works using ssh command
	sshCmd := exec.CommandContext(
		t.Context(),
		"ssh",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=no",
		container.Endpoint,
		"echo hello",
	)

	output, err := sshCmd.Output()
	if err != nil {
		t.Fatalf("SSH execute failed: %v", err)
	}

	if string(output) != "hello\n" {
		t.Errorf("expected 'hello\\n', got %q", string(output))
	}
}
