package tools

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/dev/filesystem"
)

const (
	// binaryPerms is the permission mode for installed executable binaries.
	binaryPerms = 0o755
)

// GithubRelease describes a GitHub release binary distribution.
type GithubRelease struct {
	// Name is the binary name (e.g., "buildctl").
	Name string

	// Version is the release tag (e.g., "v0.26.2").
	Version string

	// URLTemplate is the download URL template with placeholders.
	// Example: "https://github.com/moby/buildkit/releases/download/%s/buildkit-%s.%s-%s.tar.gz"
	// Use URLArgs to customize the placeholder arguments.
	URLTemplate string

	// URLArgs is a function that returns the arguments for URLTemplate.
	// Receives (version, os, arch) and returns the format arguments.
	// If nil, defaults to (version, os, arch).
	URLArgs func(version, goos, goarch string) []any

	// BinaryPathInArchive is the path to the binary within the tar.gz archive.
	// Example: "bin/buildctl".
	BinaryPathInArchive string

	// Checksums maps "os/arch" to expected SHA256 checksum of the archive.
	// Example: {"darwin/arm64": "abc123...", "linux/amd64": "def456..."}
	Checksums map[string]string
}

// githubInstaller manages installation of binaries from GitHub releases.
type githubInstaller struct {
	release       GithubRelease
	log           *slog.Logger
	installedPath string
	mu            sync.Mutex
}

// NewGithubInstaller creates a new installer for GitHub release binaries.
func NewGithubInstaller(log *slog.Logger, release GithubRelease) Installer {
	return &githubInstaller{
		release: release,
		log:     log.With("component", "github-installer", "binary", release.Name),
	}
}

// Ensure ensures the tool is installed and returns the path to the binary.
func (gi *githubInstaller) Ensure(ctx context.Context) (string, error) {
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

	binaryPath := filepath.Join(binDir, gi.release.Name)

	// Check if already installed
	if _, statErr := os.Stat(binaryPath); statErr == nil {
		gi.log.Debug("binary already installed", "path", binaryPath)
		gi.installedPath = binaryPath

		return binaryPath, nil
	}

	// Install binary
	gi.log.Info("installing binary", "version", gi.release.Version)

	if err := gi.install(ctx, binaryPath); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInstallationFailed, err)
	}

	gi.installedPath = binaryPath

	return binaryPath, nil
}

// install downloads and installs the binary for the current platform.
func (gi *githubInstaller) install(ctx context.Context, binaryPath string) error {
	// Get checksum for current platform
	expectedChecksum, err := gi.getExpectedChecksum()
	if err != nil {
		return err
	}

	// Build download URL
	downloadURL := gi.buildDownloadURL()
	gi.log.Debug("downloading binary", "url", downloadURL)

	// Download tarball
	tarballData, err := gi.download(ctx, downloadURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Verify checksum
	if err := gi.verifyChecksum(tarballData, expectedChecksum); err != nil {
		return err
	}

	gi.log.Debug("checksum verified", "sha256", expectedChecksum)

	// Extract binary from tarball
	binaryData, err := gi.extractBinary(tarballData)
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}

	// Ensure binary directory exists
	binDir := filepath.Dir(binaryPath)
	if err := os.MkdirAll(binDir, filesystem.DirPermissionsPrivate); err != nil {
		return fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
	}

	// Write binary to disk (atomic write)
	if err := filesystem.WriteFile(binaryPath, binaryData, binaryPerms); err != nil {
		return fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
	}

	gi.log.Info("binary installed successfully", "path", binaryPath, "version", gi.release.Version)

	return nil
}

// buildDownloadURL constructs the download URL using the template and current platform.
func (gi *githubInstaller) buildDownloadURL() string {
	var args []any
	if gi.release.URLArgs != nil {
		args = gi.release.URLArgs(gi.release.Version, runtime.GOOS, runtime.GOARCH)
	} else {
		args = []any{gi.release.Version, runtime.GOOS, runtime.GOARCH}
	}

	return fmt.Sprintf(gi.release.URLTemplate, args...)
}

// getExpectedChecksum returns the expected SHA256 checksum for the current platform.
func (gi *githubInstaller) getExpectedChecksum() (string, error) {
	key := runtime.GOOS + "/" + runtime.GOARCH
	checksum, ok := gi.release.Checksums[key]

	if !ok {
		return "", fmt.Errorf("%w: unsupported platform: %s", fault.ErrNotFound, key)
	}

	return checksum, nil
}

// download fetches the tarball from the given URL.
func (*githubInstaller) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrNetworkError, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", fault.ErrUnacceptableResponse, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	return data, nil
}

// verifyChecksum verifies the SHA256 checksum of the downloaded data.
func (*githubInstaller) verifyChecksum(data []byte, expected string) error {
	hash := sha256.Sum256(data)
	actual := hex.EncodeToString(hash[:])

	if actual != expected {
		return fmt.Errorf("%w: checksum mismatch (expected %s, got %s)", fault.ErrHashMismatch, expected, actual)
	}

	return nil
}

// extractBinary extracts the binary from the gzipped tarball.
func (gi *githubInstaller) extractBinary(tarballData []byte) ([]byte, error) {
	// Create gzip reader
	gzReader, err := gzip.NewReader(bytes.NewReader(tarballData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	// Find and extract binary
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		if header.Name == gi.release.BinaryPathInArchive {
			data, err := io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("%w: failed to read binary from tar: %w", fault.ErrReadFailure, err)
			}

			return data, nil
		}
	}

	return nil, fmt.Errorf("%w: binary not found in archive: %s", fault.ErrNotFound, gi.release.BinaryPathInArchive)
}
