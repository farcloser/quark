// Package tools provides auto-installation for external tools.
//
// # Installation Strategy
//
// Tools are installed using `go install <import-path>@<commit-hash>` which provides:
// - Immutable pinning: commit hashes never change (unlike tags which can be moved)
// - Reproducible builds: same commit always produces same binary
// - Security: we control exact source code being compiled
//
// # Version Pinning
//
// Commit hashes are used instead of version tags because:
// - Git tags can be deleted or moved to different commits
// - Commit SHA-256 hashes are cryptographically immutable
// - Go modules convert commit hashes to pseudo-versions automatically
//
// Example: go install github.com/aquasecurity/trivy/cmd/trivy@9aabfd2
// Go converts to: v0.0.0-20250205xxxxxx-9aabfd2 (pseudo-version)
//
// # Updating Tool Versions
//
// To update a tool:
// 1. Find the release on GitHub (e.g., github.com/aquasecurity/trivy/releases)
// 2. Get the commit hash for that release tag
// 3. Update the Version field in the Tool struct
// 4. Test with `go install <import-path>@<new-commit-hash>`
//
// Never use short commit hashes in production - always use at least 7 characters
// for collision resistance (Go will accept and expand them).
package tools

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/rs/zerolog"
)

var errToolNotInPath = errors.New("tool installed but not found in PATH")

// Tool represents an external tool that can be auto-installed.
type Tool struct {
	Name       string // Binary name (e.g., "trivy")
	ImportPath string // Go import path (e.g., "github.com/aquasecurity/trivy/cmd/trivy")
	Version    string // Commit hash for immutable pinning (e.g., "9aabfd2")
}

//nolint:gochecknoglobals
var (
	// Trivy vulnerability scanner - pinned to v0.59.1 (commit 9aabfd2).
	Trivy = Tool{
		Name:       "trivy",
		ImportPath: "github.com/aquasecurity/trivy/cmd/trivy",
		Version:    "9aabfd2", // v0.59.1 released 2025-02-05
	}

	// Dockle container image linter - pinned to v0.4.15 (commit 5436857).
	Dockle = Tool{
		Name:       "dockle",
		ImportPath: "github.com/goodwithtech/dockle/cmd/dockle",
		Version:    "5436857", // v0.4.15 released 2025-01-06
	}
)

// Installer manages tool installation.
type Installer struct {
	log       zerolog.Logger
	installed map[string]bool
	mu        sync.Mutex
}

// NewInstaller creates a new tool installer.
func NewInstaller(log zerolog.Logger) *Installer {
	return &Installer{
		log:       log,
		installed: make(map[string]bool),
	}
}

// Ensure ensures the tool is installed and available.
// Returns the path to the tool binary.
func (installer *Installer) Ensure(tool Tool) (string, error) {
	installer.mu.Lock()
	defer installer.mu.Unlock()

	// Check if already verified in this session
	if installer.installed[tool.Name] {
		installer.log.Debug().
			Str("tool", tool.Name).
			Msg("tool already verified in this session")

		return tool.Name, nil
	}

	// Check if tool is in PATH
	path, err := exec.LookPath(tool.Name)
	if err == nil {
		installer.log.Debug().
			Str("tool", tool.Name).
			Str("path", path).
			Msg("tool found in PATH")

		installer.installed[tool.Name] = true

		return path, nil
	}

	// Tool not found - install it
	installer.log.Info().
		Str("tool", tool.Name).
		Str("version", tool.Version).
		Msg("tool not found, installing...")

	if err := installer.install(tool); err != nil {
		return "", fmt.Errorf("failed to install %s: %w", tool.Name, err)
	}

	// Verify installation
	path, err = exec.LookPath(tool.Name)
	if err != nil {
		return "", fmt.Errorf("%w: %s", errToolNotInPath, tool.Name)
	}

	installer.log.Info().
		Str("tool", tool.Name).
		Str("path", path).
		Msg("tool installed successfully")

	installer.installed[tool.Name] = true

	return path, nil
}

// install installs a tool using go install with commit hash pinning.
func (installer *Installer) install(tool Tool) error {
	// Build go install command with commit hash
	// Example: go install github.com/aquasecurity/trivy/cmd/trivy@9aabfd2
	importRef := fmt.Sprintf("%s@%s", tool.ImportPath, tool.Version)

	installer.log.Debug().
		Str("import_ref", importRef).
		Msg("running go install")

	//nolint:gosec
	cmd := exec.Command("go", "install", importRef)
	cmd.Env = os.Environ()

	// Capture output for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		installer.log.Error().
			Str("output", string(output)).
			Msg("go install failed")

		return fmt.Errorf("go install failed: %w\n%s", err, output)
	}

	return nil
}

// GetToolPath returns the expected path for a tool in GOPATH/bin or GOBIN.
func (*Installer) GetToolPath(tool Tool) string {
	// Check GOBIN first
	if gobin := os.Getenv("GOBIN"); gobin != "" {
		return filepath.Join(gobin, tool.Name)
	}

	// Fall back to GOPATH/bin
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		// Default GOPATH is $HOME/go
		home, err := os.UserHomeDir()
		if err == nil {
			gopath = filepath.Join(home, "go")
		}
	}

	return filepath.Join(gopath, "bin", tool.Name)
}
