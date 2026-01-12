package tools_test

import (
	"log/slog"
	"testing"

	"github.com/farcloser/quark/dev/tools"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// INTENTION: NewGoInstaller should create a valid installer.
func TestNewGoInstaller(t *testing.T) {
	t.Parallel()

	tool := tools.GoTool{
		Name:       "test-tool",
		ImportPath: "github.com/example/test-tool",
		Version:    "v1.0.0",
	}

	installer := tools.NewGoInstaller(discardLogger(), tool)

	if installer == nil {
		t.Fatal("NewGoInstaller() returned nil, want non-nil installer")
	}
}

// INTENTION: GoTool struct should be properly initialized.
func TestGoToolStructure(t *testing.T) {
	t.Parallel()

	tool := tools.GoTool{
		Name:       "test-tool",
		ImportPath: "github.com/example/test-tool",
		Version:    "abc1234",
	}

	if tool.Name != "test-tool" {
		t.Errorf("GoTool.Name = %q, want %q", tool.Name, "test-tool")
	}

	if tool.ImportPath != "github.com/example/test-tool" {
		t.Errorf("GoTool.ImportPath = %q, want %q", tool.ImportPath, "github.com/example/test-tool")
	}

	if tool.Version != "abc1234" {
		t.Errorf("GoTool.Version = %q, want %q", tool.Version, "abc1234")
	}
}
