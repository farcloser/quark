package buildkit_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/farcloser/quark/dev/ssh"
	"github.com/farcloser/quark/internal/buildkit"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// INTENTION: NewClient should create a valid buildkit client with mock connection.
func TestNewClient_WithMockConnection(t *testing.T) {
	t.Parallel()

	mockConn := &mockSSHConnection{}

	client, err := buildkit.NewClient(mockConn, "test-node", discardLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v, want nil", err)
	}

	if client == nil {
		t.Fatal("NewClient() returned nil, want non-nil client")
	}

	// Clean up
	if err := client.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// INTENTION: DockerHost should return a valid unix socket path.
func TestClient_DockerHost(t *testing.T) {
	t.Parallel()

	mockConn := &mockSSHConnection{}

	client, err := buildkit.NewClient(mockConn, "test-node-docker-host", discardLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	defer client.Close()

	host := client.DockerHost()
	if host == "" {
		t.Error("DockerHost() returned empty string")
	}

	if len(host) < 7 || host[:7] != "unix://" {
		t.Errorf("DockerHost() = %q, want unix:// prefix", host)
	}
}

// INTENTION: BuildMultiPlatform with cancelled context should return context error.
func TestClient_BuildMultiPlatform_ContextCancelled(t *testing.T) {
	t.Parallel()

	mockConn := &mockSSHConnection{}

	client, err := buildkit.NewClient(mockConn, "test-node-build", discardLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	defer client.Close()

	// Create cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	platforms := []string{"linux/amd64", "linux/arm64"}
	tags := []string{"test:latest", "test:v1.0.0"}

	_, err = client.BuildMultiPlatform(ctx, "/tmp/context", "Dockerfile", platforms, tags, nil)

	// Should fail with context cancelled error
	if err == nil {
		t.Error("BuildMultiPlatform() error = nil, want context cancelled error")
	}
}

// INTENTION: Close should be idempotent and clean up resources.
func TestClient_Close(t *testing.T) {
	t.Parallel()

	mockConn := &mockSSHConnection{}

	client, err := buildkit.NewClient(mockConn, "test-node-close", discardLogger())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	// First close should succeed
	if err := client.Close(); err != nil {
		t.Errorf("Close() first call error = %v", err)
	}
}

// mockSSHConnection is a minimal mock implementation of ssh.Connection for testing.
type mockSSHConnection struct{}

func (*mockSSHConnection) Execute(_ string) (string, string, error) {
	return "", "", nil
}

func (*mockSSHConnection) ExecuteStreaming(_ string, _, _ io.Writer) error {
	return nil
}

func (*mockSSHConnection) ExecuteWithStdin(_ string, _ []byte) error {
	return nil
}

func (*mockSSHConnection) UploadFile(_, _ string) error {
	return nil
}

func (*mockSSHConnection) UploadData(_ []byte, _ string) error {
	return nil
}

func (*mockSSHConnection) DialUnix(_ string) (net.Conn, error) {
	return nil, ssh.ErrNotConnected
}

// Ensure mockSSHConnection implements ssh.Connection at compile time.
var _ ssh.Connection = (*mockSSHConnection)(nil)
