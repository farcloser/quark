package tools_test

import (
	"log/slog"
	"testing"

	"github.com/farcloser/quark/internal/tools"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// INTENTION: NewInstaller should create a valid installer.
func TestNewInstaller(t *testing.T) {
	t.Parallel()

	installer := tools.NewInstaller(discardLogger())

	if installer == nil {
		t.Fatal("NewInstaller() returned nil, want non-nil installer")
	}
}

// INTENTION: Tool struct should be properly initialized.
func TestToolStructure(t *testing.T) {
	t.Parallel()

	// Test that Tool struct can be created with required fields
	tool := tools.Tool{
		Name:       "test-tool",
		ImportPath: "github.com/example/test-tool",
		Version:    "abc1234",
	}

	if tool.Name != "test-tool" {
		t.Errorf("Tool.Name = %q, want %q", tool.Name, "test-tool")
	}

	if tool.ImportPath != "github.com/example/test-tool" {
		t.Errorf("Tool.ImportPath = %q, want %q", tool.ImportPath, "github.com/example/test-tool")
	}

	if tool.Version != "abc1234" {
		t.Errorf("Tool.Version = %q, want %q", tool.Version, "abc1234")
	}
}
