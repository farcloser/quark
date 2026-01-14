package sshprime_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/farcloser/quark/pkg/core/sshprime"
	testssh "github.com/farcloser/quark/testutil/ssh"
)

const skipIntegrationMsg = "skipping integration test in short mode"

// getClient creates a new SSH client connected to the test container.
// It uses explicit fingerprint trust to avoid relying on system known_hosts.
func getClient(t *testing.T, container *testssh.Container) *sshprime.Client {
	t.Helper()

	endpoint, err := sshprime.Resolve(container.Endpoint, false)
	if err != nil {
		t.Fatalf("failed to resolve endpoint: %v", err)
	}

	// Get and trust the host fingerprint (avoids known_hosts dependency)
	fingerprint := testssh.GetHostFingerprint(t, container.Host)
	sshprime.GetFingerprinter().Trust(endpoint, fingerprint)

	t.Cleanup(func() {
		sshprime.GetFingerprinter().Clear(endpoint)
	})

	// Load test key and use withSSHConfig=false to avoid known_hosts
	testKey := testssh.GetTestKey(t)

	config, err := sshprime.GetClientConfig([]*sshprime.Key{testKey}, endpoint, false)
	if err != nil {
		t.Fatalf("failed to get client config: %v", err)
	}

	addr := fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)

	client, err := sshprime.NewClient(addr, config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	t.Cleanup(func() {
		_ = client.Close()
	})

	return client
}

func TestClient_Execute(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip(skipIntegrationMsg)
	}

	container := testssh.EnsureDebianContainer(t)
	client := getClient(t, container)

	t.Run("captures stdout", func(t *testing.T) {
		t.Parallel()

		stdout, stderr, err := client.Execute("echo 'hello world'", nil)
		if err != nil {
			t.Fatalf("expected command to succeed, got error: %v", err)
		}

		if !strings.Contains(stdout, "hello world") {
			t.Errorf("expected stdout to contain 'hello world', got: %q", stdout)
		}

		if stderr != "" {
			t.Errorf("expected empty stderr, got: %q", stderr)
		}
	})

	t.Run("captures stderr", func(t *testing.T) {
		t.Parallel()

		stdout, stderr, err := client.Execute("echo 'error message' >&2", nil)
		if err != nil {
			t.Fatalf("expected command to succeed, got error: %v", err)
		}

		if stdout != "" {
			t.Errorf("expected empty stdout, got: %q", stdout)
		}

		if !strings.Contains(stderr, "error message") {
			t.Errorf("expected stderr to contain 'error message', got: %q", stderr)
		}
	})

	t.Run("returns error for failing command", func(t *testing.T) {
		t.Parallel()

		_, _, err := client.Execute("exit 1", nil)
		if err == nil {
			t.Fatal("expected error for command with exit code 1")
		}

		if !errors.Is(err, sshprime.ErrCommandFailed) {
			t.Errorf("expected ErrCommandFailed, got: %v", err)
		}
	})

	t.Run("returns error for nonexistent command", func(t *testing.T) {
		t.Parallel()

		_, stderr, err := client.Execute("nonexistent_command_xyz123", nil)
		if err == nil {
			t.Fatal("expected error for nonexistent command")
		}

		if !strings.Contains(stderr, "not found") {
			t.Errorf("expected stderr to contain 'not found', got: %q", stderr)
		}
	})

	t.Run("handles stdin input", func(t *testing.T) {
		t.Parallel()

		input := []byte("line1\nline2\nline3\n")

		stdout, _, err := client.Execute("cat", input)
		if err != nil {
			t.Fatalf("expected command to succeed, got error: %v", err)
		}

		if stdout != string(input) {
			t.Errorf("expected stdout to match input, got: %q, want: %q", stdout, string(input))
		}
	})

	t.Run("handles binary stdin", func(t *testing.T) {
		t.Parallel()

		// Binary data with null bytes
		input := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}

		stdout, _, err := client.Execute("cat | wc -c", input)
		if err != nil {
			t.Fatalf("expected command to succeed, got error: %v", err)
		}

		if !strings.Contains(stdout, "6") {
			t.Errorf("expected wc -c to report 6 bytes, got: %q", stdout)
		}
	})

	t.Run("handles complex output", func(t *testing.T) {
		t.Parallel()

		stdout, _, err := client.Execute("ls -la /", nil)
		if err != nil {
			t.Fatalf("expected ls command to succeed, got error: %v", err)
		}

		// Verify directory listing contains expected entries
		if !strings.Contains(stdout, "bin") || !strings.Contains(stdout, "etc") {
			t.Errorf("expected directory listing to contain 'bin' and 'etc', got: %q", stdout)
		}
	})

	t.Run("multiple sequential commands reuse connection", func(t *testing.T) {
		t.Parallel()

		for i := range 5 {
			stdout, _, err := client.Execute(fmt.Sprintf("echo 'iteration %d'", i), nil)
			if err != nil {
				t.Fatalf("command %d failed: %v", i, err)
			}

			expected := fmt.Sprintf("iteration %d", i)
			if !strings.Contains(stdout, expected) {
				t.Errorf("command %d: expected %q in output, got: %q", i, expected, stdout)
			}
		}
	})
}

func TestClient_ExecuteStreaming(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip(skipIntegrationMsg)
	}

	container := testssh.EnsureDebianContainer(t)
	client := getClient(t, container)

	t.Run("streams stdout to writer", func(t *testing.T) {
		t.Parallel()

		var stdout bytes.Buffer

		err := client.ExecuteStreaming("echo 'streamed output'", &stdout, nil, nil)
		if err != nil {
			t.Fatalf("expected command to succeed, got error: %v", err)
		}

		if !strings.Contains(stdout.String(), "streamed output") {
			t.Errorf("expected stdout to contain 'streamed output', got: %q", stdout.String())
		}
	})

	t.Run("streams stderr to writer", func(t *testing.T) {
		t.Parallel()

		var stdout, stderr bytes.Buffer

		err := client.ExecuteStreaming("echo 'error output' >&2", &stdout, &stderr, nil)
		if err != nil {
			t.Fatalf("expected command to succeed, got error: %v", err)
		}

		if stdout.Len() != 0 {
			t.Errorf("expected empty stdout, got: %q", stdout.String())
		}

		if !strings.Contains(stderr.String(), "error output") {
			t.Errorf("expected stderr to contain 'error output', got: %q", stderr.String())
		}
	})

	t.Run("handles stdin with streaming", func(t *testing.T) {
		t.Parallel()

		var stdout bytes.Buffer

		input := []byte("streaming input data\n")

		err := client.ExecuteStreaming("cat", &stdout, nil, input)
		if err != nil {
			t.Fatalf("expected command to succeed, got error: %v", err)
		}

		if stdout.String() != string(input) {
			t.Errorf("expected stdout to match input, got: %q, want: %q", stdout.String(), string(input))
		}
	})

	t.Run("returns error for failing command", func(t *testing.T) {
		t.Parallel()

		var stdout bytes.Buffer

		err := client.ExecuteStreaming("exit 42", &stdout, nil, nil)
		if err == nil {
			t.Fatal("expected error for command with exit code 42")
		}

		if !errors.Is(err, sshprime.ErrCommandFailed) {
			t.Errorf("expected ErrCommandFailed, got: %v", err)
		}
	})
}

func TestClient_Close(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip(skipIntegrationMsg)
	}

	container := testssh.EnsureDebianContainer(t)

	endpoint, err := sshprime.Resolve(container.Endpoint, false)
	if err != nil {
		t.Fatalf("failed to resolve endpoint: %v", err)
	}

	// Trust fingerprint to avoid known_hosts dependency
	fingerprint := testssh.GetHostFingerprint(t, container.Host)
	sshprime.GetFingerprinter().Trust(endpoint, fingerprint)

	t.Cleanup(func() {
		sshprime.GetFingerprinter().Clear(endpoint)
	})

	testKey := testssh.GetTestKey(t)

	config, err := sshprime.GetClientConfig([]*sshprime.Key{testKey}, endpoint, false)
	if err != nil {
		t.Fatalf("failed to get client config: %v", err)
	}

	addr := fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)

	client, err := sshprime.NewClient(addr, config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Verify connection works before close
	_, _, err = client.Execute("echo 'before close'", nil)
	if err != nil {
		t.Fatalf("command before close failed: %v", err)
	}

	// Close the client
	if err := client.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestSFTPClient_UploadData(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip(skipIntegrationMsg)
	}

	container := testssh.EnsureDebianContainer(t)
	client := getClient(t, container)

	sftpClient, err := sshprime.NewSFTPClient(client)
	if err != nil {
		t.Fatalf("failed to create SFTP client: %v", err)
	}

	t.Cleanup(func() {
		_ = sftpClient.Close()
	})

	t.Run("uploads data to remote file", func(t *testing.T) {
		t.Parallel()

		remotePath := "/tmp/test-upload-data.txt"
		data := []byte("test content from upload data")

		if err := sftpClient.UploadData(data, remotePath); err != nil {
			t.Fatalf("UploadData failed: %v", err)
		}

		// Verify file exists and has correct content
		stdout, _, err := client.Execute("cat "+remotePath, nil)
		if err != nil {
			t.Fatalf("failed to read uploaded file: %v", err)
		}

		if stdout != string(data) {
			t.Errorf("file content = %q, want %q", stdout, string(data))
		}
	})

	t.Run("sets restrictive permissions", func(t *testing.T) {
		t.Parallel()

		remotePath := "/tmp/test-upload-perms.txt"
		data := []byte("secret data")

		if err := sftpClient.UploadData(data, remotePath); err != nil {
			t.Fatalf("UploadData failed: %v", err)
		}

		// Check file permissions
		stdout, _, err := client.Execute("stat -c '%a' "+remotePath, nil)
		if err != nil {
			t.Fatalf("failed to stat file: %v", err)
		}

		perms := strings.TrimSpace(stdout)
		if perms != "600" {
			t.Errorf("file permissions = %s, want 600", perms)
		}
	})

	t.Run("overwrites existing file", func(t *testing.T) {
		t.Parallel()

		remotePath := "/tmp/test-upload-overwrite.txt"

		// Upload initial content
		if err := sftpClient.UploadData([]byte("original content"), remotePath); err != nil {
			t.Fatalf("first UploadData failed: %v", err)
		}

		// Upload new content
		newData := []byte("new content")
		if err := sftpClient.UploadData(newData, remotePath); err != nil {
			t.Fatalf("second UploadData failed: %v", err)
		}

		// Verify file has new content
		stdout, _, err := client.Execute("cat "+remotePath, nil)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		if stdout != string(newData) {
			t.Errorf("file content = %q, want %q", stdout, string(newData))
		}
	})
}

func TestSFTPClient_UploadFile(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip(skipIntegrationMsg)
	}

	container := testssh.EnsureDebianContainer(t)
	client := getClient(t, container)

	sftpClient, err := sshprime.NewSFTPClient(client)
	if err != nil {
		t.Fatalf("failed to create SFTP client: %v", err)
	}

	t.Cleanup(func() {
		_ = sftpClient.Close()
	})

	t.Run("uploads local file to remote", func(t *testing.T) {
		t.Parallel()

		// Create temporary local file
		localDir := t.TempDir()
		localPath := filepath.Join(localDir, "test-file.txt")
		content := []byte("content from local file\n")

		if err := os.WriteFile(localPath, content, 0o600); err != nil {
			t.Fatalf("failed to create local file: %v", err)
		}

		remotePath := "/tmp/test-upload-file.txt"

		if err := sftpClient.UploadFile(localPath, remotePath); err != nil {
			t.Fatalf("UploadFile failed: %v", err)
		}

		// Verify file exists and has correct content
		stdout, _, err := client.Execute("cat "+remotePath, nil)
		if err != nil {
			t.Fatalf("failed to read uploaded file: %v", err)
		}

		if stdout != string(content) {
			t.Errorf("file content = %q, want %q", stdout, string(content))
		}
	})

	t.Run("returns error for nonexistent local file", func(t *testing.T) {
		t.Parallel()

		err := sftpClient.UploadFile("/nonexistent/path/file.txt", "/tmp/dest.txt")
		if err == nil {
			t.Error("expected error for nonexistent local file")
		}
	})
}

func TestNewClient_ConnectionFailure(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip(skipIntegrationMsg)
	}

	// Try to connect to a non-routable address
	endpoint := &sshprime.Endpoint{
		User: "test",
		Host: "192.0.2.1", // TEST-NET-1, guaranteed non-routable
		Port: 22,
	}

	config, err := sshprime.GetClientConfig(nil, endpoint, false)
	if err != nil {
		t.Fatalf("failed to get client config: %v", err)
	}

	addr := fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)

	_, err = sshprime.NewClient(addr, config)
	if err == nil {
		t.Error("expected connection to fail for non-routable address")
	}
}
