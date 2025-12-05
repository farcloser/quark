package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/farcloser/quark/internal/utilities"
)

// Tool represents an external tool that can be auto-installed.
type Tool struct {
	Name       string // Binary name (e.g., "trivy")
	ImportPath string // Go import path (e.g., "github.com/aquasecurity/trivy/cmd/trivy")
	Version    string // Commit hash for immutable pinning (e.g., "9aabfd2")
}

// Installer manages tool installation.
type Installer struct {
	log       *slog.Logger
	installed map[string]string
	mu        sync.Mutex
}

// NewInstaller creates a new tool installer.
func NewInstaller(log *slog.Logger) *Installer {
	return &Installer{
		log:       log.With("component", "installer"),
		installed: make(map[string]string),
	}
}

// Ensure ensures the tool is installed and available.
// Returns the path to the tool binary.
func (installer *Installer) Ensure(ctx context.Context, tool Tool) (string, error) {
	// Check context before acquiring lock
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", utilities.ErrCancelled, err)
	}

	installer.mu.Lock()
	defer installer.mu.Unlock()

	// Check if already verified in this session
	if installer.installed[tool.Name] != "" {
		installer.log.Debug("tool already verified in this session", "tool", tool.Name)

		return installer.installed[tool.Name], nil
	}

	// Get the expected tool path (GOBIN or GOPATH/bin)
	toolPath := installer.getToolPath(tool)

	// Check if tool exists at the expected path
	if _, err := os.Stat(toolPath); err == nil {
		installer.log.Debug("tool found", "tool", tool.Name, "path", toolPath)

		installer.installed[tool.Name] = toolPath

		return toolPath, nil
	}

	// Tool not found - install it
	installer.log.Debug(
		"tool not found, installing...",
		"tool", //revive:disable-line:add-constant
		tool.Name,
		"version",
		tool.Version,
	)

	if err := installer.install(ctx, tool); err != nil {
		return "", err
	}

	// Verify installation
	if _, err := os.Stat(toolPath); err != nil {
		return "", fmt.Errorf("%w: %s (expected at %s)", ErrToolNotInstalled, tool.Name, toolPath)
	}

	installer.log.Debug("tool installed successfully", "tool", tool.Name, "path", toolPath)

	installer.installed[tool.Name] = toolPath

	return toolPath, nil
}

// install installs a tool using go install with commit hash pinning.
func (installer *Installer) install(ctx context.Context, tool Tool) error {
	// Build go install command with commit hash
	// Example: go install github.com/aquasecurity/trivy/cmd/trivy@9aabfd2
	importRef := fmt.Sprintf("%s@%s", tool.ImportPath, tool.Version)

	installer.log.Debug("running go install", "import_ref", importRef)

	//nolint:gosec
	cmd := exec.CommandContext(ctx, "go", "install", importRef)
	cmd.Env = os.Environ()

	// Capture output for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %w\n%s", ErrUnableToInstall, err, output)
	}

	return nil
}

// getToolPath returns the expected path for a tool in GOPATH/bin or GOBIN.
func (*Installer) getToolPath(tool Tool) string {
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
