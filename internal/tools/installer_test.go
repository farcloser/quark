package tools_test

import (
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/tools"
)

// INTENTION: NewInstaller should create a valid installer.
func TestNewInstaller(t *testing.T) {
	t.Parallel()

	installer := tools.NewInstaller(zerolog.Nop())

	if installer == nil {
		t.Fatal("NewInstaller() returned nil, want non-nil installer")
	}
}

// INTENTION: Tool struct should contain required fields.
func TestToolStructure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tool tools.Tool
	}{
		{
			name: "Trivy tool",
			tool: tools.Trivy,
		},
		{
			name: "Dockle tool",
			tool: tools.Dockle,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.tool.Name == "" {
				t.Error("Tool.Name is empty, want non-empty name")
			}

			if tt.tool.ImportPath == "" {
				t.Error("Tool.ImportPath is empty, want non-empty import path")
			}

			if tt.tool.Version == "" {
				t.Error("Tool.Version is empty, want non-empty version")
			}
		})
	}
}

// INTENTION: GetToolPath should return expected path structure.
func TestInstaller_GetToolPath(t *testing.T) {
	tests := []struct {
		name   string
		tool   tools.Tool
		gobin  string
		gopath string
	}{
		{
			name:   "Trivy with GOBIN",
			tool:   tools.Trivy,
			gobin:  "/custom/gobin",
			gopath: "",
		},
		{
			name:   "Dockle with GOPATH",
			tool:   tools.Dockle,
			gobin:  "",
			gopath: "/custom/gopath",
		},
		{
			name:   "Trivy with default",
			tool:   tools.Trivy,
			gobin:  "",
			gopath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.gobin != "" {
				t.Setenv("GOBIN", tt.gobin)
			}

			if tt.gopath != "" {
				t.Setenv("GOPATH", tt.gopath)
			}

			installer := tools.NewInstaller(zerolog.Nop())
			path := installer.GetToolPath(tt.tool)

			// Verify path ends with tool name
			expectedSuffix := string(filepath.Separator) + tt.tool.Name

			if len(path) < len(expectedSuffix) || path[len(path)-len(expectedSuffix):] != expectedSuffix {
				t.Errorf("GetToolPath() = %q, want path ending with %q", path, expectedSuffix)
			}

			// Verify path contains expected directory
			if tt.gobin != "" {
				if !contains(path, tt.gobin) {
					t.Errorf("GetToolPath() = %q, want path containing GOBIN %q", path, tt.gobin)
				}
			} else if tt.gopath != "" {
				expectedDir := filepath.Join(tt.gopath, "bin")
				if !contains(path, expectedDir) {
					t.Errorf("GetToolPath() = %q, want path containing GOPATH/bin %q", path, expectedDir)
				}
			}
		})
	}
}

// INTENTION: Ensure should not panic when tool is not found.
// Note: This test may actually install the tool if 'go install' succeeds.
//

func TestInstaller_Ensure_ToolNotInPath(t *testing.T) {
	t.Parallel()

	// Skip this test as it would actually install trivy
	t.Skip("Skipping - would install real tools")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}

	return false
}
