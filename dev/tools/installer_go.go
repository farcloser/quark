package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/dev/filesystem"
)

// GoTool describes a Go tool that can be installed via `go install`.
type GoTool struct {
	// Name is the binary name (e.g., "trivy").
	Name string

	// ImportPath is the Go import path (e.g., "github.com/aquasecurity/trivy/cmd/trivy").
	ImportPath string

	// Version is the version or commit hash for pinning (e.g., "v0.50.0" or "9aabfd2").
	Version string
}

// goInstaller manages installation of Go tools via `go install`.
type goInstaller struct {
	tool          GoTool
	log           *slog.Logger
	installedPath string
	mu            sync.Mutex
}

// NewGoInstaller creates a new installer for Go tools.
func NewGoInstaller(log *slog.Logger, tool GoTool) Installer {
	return &goInstaller{
		tool: tool,
		log:  log.With("component", "go-installer", "binary", tool.Name),
	}
}

// Ensure ensures the tool is installed and returns the path to the binary.
func (gi *goInstaller) Ensure(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", fault.ErrCancelled, err)
	}

	gi.mu.Lock()
	defer gi.mu.Unlock()

	// Return cached path if already verified this session
	if gi.installedPath != "" {
		return gi.installedPath, nil
	}

	// Get binary path
	binDir, err := filesystem.BinDir()
	if err != nil {
		return "", fmt.Errorf("%w: failed to get binary path: %w", ErrInstallationFailed, err)
	}

	binaryPath := filepath.Join(binDir, gi.tool.Name)

	// Check if binary exists at the expected path
	if _, err := os.Stat(binaryPath); err == nil {
		gi.log.Debug("binary already installed", "path", binaryPath)
		gi.installedPath = binaryPath

		return binaryPath, nil
	}

	// Binary not found - install it
	gi.log.Info("installing binary", "version", gi.tool.Version)

	if err := gi.install(ctx, binDir); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInstallationFailed, err)
	}

	// Verify installation
	if _, err := os.Stat(binaryPath); err != nil {
		return "", fmt.Errorf("%w: %s not found at %s", ErrInstallationFailed, gi.tool.Name, binaryPath)
	}

	gi.log.Debug("binary installed successfully", "path", binaryPath)
	gi.installedPath = binaryPath

	return binaryPath, nil
}

// install installs the tool using go install with version pinning.
func (gi *goInstaller) install(ctx context.Context, binDir string) error {
	// Build go install command with version
	// Example: go install github.com/aquasecurity/trivy/cmd/trivy@v0.50.0
	importRef := fmt.Sprintf("%s@%s", gi.tool.ImportPath, gi.tool.Version)

	gi.log.Debug("running go install", "import_ref", importRef, "gobin", binDir)

	//nolint:gosec
	cmd := exec.CommandContext(ctx, "go", "install", importRef)

	// Set GOBIN to quark's private bin directory
	cmd.Env = append(os.Environ(), "GOBIN="+binDir)

	// Capture output for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}

	return nil
}
