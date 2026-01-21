package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/core/trust"
	"github.com/farcloser/quark/pkg/fault"
)

// GoTool describes a Go tool that can be installed via `go install`.
type GoTool struct {
	// Name is the binary name (e.g., "trivy").
	Name string

	// ImportPath is the Go import path (e.g., "github.com/aquasecurity/trivy/cmd/trivy").
	ImportPath string

	// Version is the version or commit hash for pinning (e.g., "v0.50.0" or "9aabfd2").
	Version string

	mu            sync.Mutex
	installedPath string
}

// Ensure ensures the tool is installed and returns the path to the binary.
func (gi *GoTool) Ensure(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", fault.ErrCancelled, err)
	}

	// Validate tool name is filesystem-safe
	if err := filesystem.ValidatePathComponent(gi.Name); err != nil {
		return "", fmt.Errorf("%w: invalid tool name %q: %w", ErrInstallationFailed, gi.Name, err)
	}

	gi.mu.Lock()
	defer gi.mu.Unlock()

	// Return cached path if already verified this session
	if gi.installedPath != "" {
		return gi.installedPath, nil
	}

	// Get base binary directory
	binDir, err := filesystem.BinDir()
	if err != nil {
		return "", fmt.Errorf("%w: failed to get binary path: %w", ErrInstallationFailed, err)
	}

	// Version-specific directory: binDir/toolName-version/
	versionedDir := filepath.Join(binDir, fmt.Sprintf("%s-%s", gi.Name, trust.HashString(gi.Version)))
	binaryPath := filepath.Join(versionedDir, gi.Name)

	// Check if binary exists at the expected versioned path
	if _, err := os.Stat(binaryPath); err == nil {
		slog.Debug("binary already installed", "path", binaryPath, "version", gi.Version)
		gi.installedPath = binaryPath

		return binaryPath, nil
	}

	// Binary not found - install it
	slog.Info("installing binary", "version", gi.Version)

	if err := gi.install(ctx, versionedDir); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInstallationFailed, err)
	}

	// Verify installation
	if _, err := os.Stat(binaryPath); err != nil {
		return "", fmt.Errorf("%w: %s not found at %s", ErrInstallationFailed, gi.Name, binaryPath)
	}

	slog.Debug("binary installed successfully", "path", binaryPath, "version", gi.Version)
	gi.installedPath = binaryPath

	return binaryPath, nil
}

// install installs the tool using go install with version pinning.
func (gi *GoTool) install(ctx context.Context, binDir string) error {
	// Ensure the versioned directory exists
	if err := os.MkdirAll(binDir, filesystem.DirPermissionsPrivate); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", binDir, err)
	}

	// Build go install command with version
	// Example: go install github.com/aquasecurity/trivy/cmd/trivy@v0.50.0
	importRef := fmt.Sprintf("%s@%s", gi.ImportPath, gi.Version)

	slog.Debug("running go install", "import_ref", importRef, "gobin", binDir)

	gopath, err := EnsureGo(ctx)
	if err != nil {
		return err
	}

	//nolint:gosec
	cmd := exec.CommandContext(ctx, gopath, "install", importRef)

	// Set GOBIN to versioned directory
	cmd.Env = append(os.Environ(), "GOBIN="+binDir)

	// Capture output for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}

	return nil
}
