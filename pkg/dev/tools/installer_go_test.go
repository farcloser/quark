package tools_test

import (
	"testing"

	"github.com/farcloser/quark/pkg/dev/tools"
)

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
