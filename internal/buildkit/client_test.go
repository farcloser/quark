package buildkit_test

import (
	"context"
	"io"
	"testing"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/buildkit"
	"github.com/farcloser/quark/ssh"
)

// INTENTION: NewClient should create a valid buildkit client.
func TestNewClient(t *testing.T) {
	t.Parallel()

	// Note: NewClient accepts nil ssh.Connection (will panic at execution time)
	// This documents current behavior - nil check happens at execution, not construction
	client := buildkit.NewClient(nil, zerolog.Nop())

	if client == nil {
		t.Fatal("NewClient() returned nil, want non-nil client")
	}
}

// INTENTION: Build with cancelled context should return context error.
func TestClient_Build_ContextCancelled(t *testing.T) {
	t.Parallel()

	client := buildkit.NewClient(nil, zerolog.Nop())

	// Create cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	tag, err := client.Build(ctx, "/tmp/context", "Dockerfile", "linux/amd64")

	// Should fail with context cancelled error
	if err == nil {
		t.Error("Build() error = nil, want context cancelled error")
	}

	if tag != "" {
		t.Errorf("Build() tag = %q, want empty string on cancelled context", tag)
	}
}

// INTENTION: BuildMultiPlatform with cancelled context should return context error.
func TestClient_BuildMultiPlatform_ContextCancelled(t *testing.T) {
	t.Parallel()

	client := buildkit.NewClient(nil, zerolog.Nop())

	// Create cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	platforms := []string{"linux/amd64", "linux/arm64"}

	tag, err := client.BuildMultiPlatform(ctx, "/tmp/context", "Dockerfile", platforms, "test:latest")

	// Should fail with context cancelled error
	if err == nil {
		t.Error("BuildMultiPlatform() error = nil, want context cancelled error")
	}

	if tag != "" {
		t.Errorf("BuildMultiPlatform() tag = %q, want empty string on cancelled context", tag)
	}
}

// INTENTION: NewClient with valid ssh.Connection creates client.
// Note: This test uses a mock connection to verify client creation works.
func TestNewClient_WithMockConnection(t *testing.T) {
	t.Parallel()

	// Create a mock SSH connection (implements ssh.Connection interface)
	mockConn := &mockSSHConnection{}

	client := buildkit.NewClient(mockConn, zerolog.Nop())

	if client == nil {
		t.Fatal("NewClient() returned nil, want non-nil client with mock connection")
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

func (*mockSSHConnection) UploadFile(_, _ string) error {
	return nil
}

func (*mockSSHConnection) UploadData(_ []byte, _ string) error {
	return nil
}

// Ensure mockSSHConnection implements ssh.Connection at compile time.
var _ ssh.Connection = (*mockSSHConnection)(nil)
