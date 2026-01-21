package tools

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/core/trust"
	"github.com/farcloser/quark/pkg/dev/network"
	"github.com/farcloser/quark/pkg/fault"
)

const (
	// maxExtractSize is the maximum total bytes that can be extracted from an archive.
	// Prevents decompression bomb attacks (small compressed file expanding to huge size).
	maxExtractSize = 2 << 30 // 2 GiB
)

// Magic bytes for archive detection.
//
//nolint:gochecknoglobals // Read-only lookup table
var (
	magicGzip = []byte{0x1f, 0x8b}
	magicZip  = []byte{0x50, 0x4b, 0x03, 0x04}
)

// HTTPRelease describes a binary distribution from any HTTP source.
// Archive type (tar.gz, zip, or raw binary) is auto-detected from content.
type HTTPRelease struct {
	// Name is the binary name (e.g., "buildctl", "go").
	Name string

	// Version is the release version (e.g., "v0.26.2", "1.22.0").
	Version string

	// URLTemplate is the download URL template with placeholders.
	// Example: "https://go.dev/dl/go%s.%s-%s.tar.gz"
	// Use URLArgs to customize the placeholder arguments.
	URLTemplate string

	// URLArgs is a function that returns the arguments for URLTemplate.
	// Receives (version, os, arch) and returns the format arguments.
	// If nil, defaults to (version, os, arch).
	URLArgs func(version, goos, goarch string) []any

	// PathInArchive is the path to extract from the archive.
	// If set, extracts only that file to versionedDir/Name.
	// If empty, extracts the entire archive to versionedDir.
	PathInArchive string

	// Checksums maps "os/arch" to expected checksum of the download.
	// Example: {"darwin/arm64": "sha256:abc...", "linux/amd64": "sha256:def..."}
	Checksums map[string]string

	installedPath string
	mu            sync.Mutex
}

// Ensure ensures the tool is installed and returns the path to the binary.
func (gi *HTTPRelease) Ensure(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", fault.ErrCancelled, err)
	}

	// Validate release name is filesystem-safe
	if err := filesystem.ValidatePathComponent(gi.Name); err != nil {
		return "", fmt.Errorf("%w: invalid release name %q: %w", ErrInstallationFailed, gi.Name, err)
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

	// Version-specific directory: binDir/toolName-versionHash/
	versionedDir := filepath.Join(binDir, fmt.Sprintf("%s-%s", gi.Name, trust.HashString(gi.Version)))

	// Determine installed path based on extraction mode
	var installedPath string
	if gi.PathInArchive != "" {
		// Single file extraction: return path to binary
		installedPath = filepath.Join(versionedDir, gi.Name)
	} else {
		// Full archive extraction: return directory
		installedPath = versionedDir
	}

	// Check if already installed at versioned path.
	if _, statErr := os.Stat(installedPath); statErr == nil {
		slog.Debug("already installed", "path", installedPath, "version", gi.Version)
		gi.installedPath = installedPath

		return installedPath, nil
	}

	// Install
	slog.Info("installing", "version", gi.Version)

	if err := gi.install(ctx, versionedDir); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInstallationFailed, err)
	}

	gi.installedPath = installedPath

	return installedPath, nil
}

// install downloads and installs the release for the current platform.
func (gi *HTTPRelease) install(ctx context.Context, versionedDir string) error {
	// Get checksum for current platform
	key := runtime.GOOS + "/" + runtime.GOARCH
	expectedChecksum, ok := gi.Checksums[key]

	if !ok {
		return fmt.Errorf("%w: unsupported platform: %s", fault.ErrNotFound, key)
	}

	// Build download URL
	var args []any
	if gi.URLArgs != nil {
		args = gi.URLArgs(gi.Version, runtime.GOOS, runtime.GOARCH)
	} else {
		args = []any{gi.Version, runtime.GOOS, runtime.GOARCH}
	}

	downloadURL := fmt.Sprintf(gi.URLTemplate, args...)

	slog.Debug("downloading", "url", downloadURL)

	// Download with cache and checksum verification
	data, err := network.FetchWithCache(ctx, downloadURL, expectedChecksum)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	slog.Debug("checksum verified", "checksum", expectedChecksum)

	if gi.PathInArchive != "" {
		// Single file extraction - filesystem.WriteFile is already atomic
		binaryData, err := gi.extractFile(data)
		if err != nil {
			return fmt.Errorf("extraction failed: %w", err)
		}

		if err := os.MkdirAll(versionedDir, filesystem.DirPermissionsPrivate); err != nil {
			return fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
		}

		if err := filesystem.WriteFile(filepath.Join(versionedDir, gi.Name), binaryData, filesystem.FilePermissionsPrivate|0o100); err != nil {
			return fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
		}
	} else {
		// Full archive extraction - use temp directory for atomic directory creation
		tempDir := versionedDir + ".tmp"

		// Clean up any stale temp directory from previous failed attempt
		_ = os.RemoveAll(tempDir)

		if err := os.MkdirAll(tempDir, filesystem.DirPermissionsPrivate); err != nil {
			return fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
		}

		if err := gi.extractAll(data, tempDir); err != nil {
			_ = os.RemoveAll(tempDir)

			return fmt.Errorf("extraction failed: %w", err)
		}

		// Atomic rename: temp -> final
		if err := os.Rename(tempDir, versionedDir); err != nil {
			_ = os.RemoveAll(tempDir)

			// Check if another process completed the installation
			if _, statErr := os.Stat(versionedDir); statErr == nil {
				slog.Debug("installation completed by another process", "path", versionedDir)

				return nil
			}

			return fmt.Errorf("%w: failed to finalize installation: %w", fault.ErrFilesystemFailure, err)
		}
	}

	slog.Info("installed", "path", versionedDir, "version", gi.Version)

	return nil
}

// extractFile extracts a single file from the archive.
// Archive type is auto-detected from magic bytes.
func (gi *HTTPRelease) extractFile(data []byte) ([]byte, error) {
	switch {
	case len(data) >= len(magicGzip) && bytes.Equal(data[:len(magicGzip)], magicGzip):
		return gi.extractFileFromTarGz(data)
	case len(data) >= len(magicZip) && bytes.Equal(data[:len(magicZip)], magicZip):
		return gi.extractFileFromZip(data)
	default:
		return nil, fmt.Errorf("%w: unknown archive format", fault.ErrInvalidArgument)
	}
}

// extractFileFromTarGz extracts a single file from a gzipped tarball.
func (gi *HTTPRelease) extractFileFromTarGz(data []byte) ([]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		if header.Name == gi.PathInArchive {
			// Limit read size to prevent decompression bombs
			limited := io.LimitReader(tarReader, maxExtractSize+1)

			fileData, err := io.ReadAll(limited)
			if err != nil {
				return nil, fmt.Errorf("%w: failed to read file from tar: %w", fault.ErrReadFailure, err)
			}

			if int64(len(fileData)) > maxExtractSize {
				return nil, fmt.Errorf(
					"%w: file exceeds maximum size (%d bytes)",
					fault.ErrInvalidArgument,
					maxExtractSize,
				)
			}

			return fileData, nil
		}
	}

	return nil, fmt.Errorf("%w: file not found in archive: %s", fault.ErrNotFound, gi.PathInArchive)
}

// extractFileFromZip extracts a single file from a zip archive.
func (gi *HTTPRelease) extractFileFromZip(data []byte) ([]byte, error) {
	zipReader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to create zip reader: %w", err)
	}

	for _, file := range zipReader.File {
		if file.Name == gi.PathInArchive {
			reader, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open file in zip: %w", err)
			}

			// Limit read size to prevent decompression bombs
			limited := io.LimitReader(reader, maxExtractSize+1)

			fileData, err := io.ReadAll(limited)
			_ = reader.Close()

			if err != nil {
				return nil, fmt.Errorf("%w: failed to read file from zip: %w", fault.ErrReadFailure, err)
			}

			if int64(len(fileData)) > maxExtractSize {
				return nil, fmt.Errorf(
					"%w: file exceeds maximum size (%d bytes)",
					fault.ErrInvalidArgument,
					maxExtractSize,
				)
			}

			return fileData, nil
		}
	}

	return nil, fmt.Errorf("%w: file not found in archive: %s", fault.ErrNotFound, gi.PathInArchive)
}

// extractAll extracts the entire archive to destDir.
// Archive type is auto-detected from magic bytes.
func (gi *HTTPRelease) extractAll(data []byte, destDir string) error {
	switch {
	case len(data) >= len(magicGzip) && bytes.Equal(data[:len(magicGzip)], magicGzip):
		return gi.extractAllFromTarGz(data, destDir)
	case len(data) >= len(magicZip) && bytes.Equal(data[:len(magicZip)], magicZip):
		return gi.extractAllFromZip(data, destDir)
	default:
		return fmt.Errorf("%w: unknown archive format", fault.ErrInvalidArgument)
	}
}

// extractAllFromTarGz extracts all files from a gzipped tarball.
func (*HTTPRelease) extractAllFromTarGz(data []byte, destDir string) error {
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	budget := newExtractionBudget(maxExtractSize)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Security: prevent path traversal
		targetPath := filepath.Join(destDir, header.Name) //nolint:gosec // path is validated below
		if !isSubPath(destDir, targetPath) {
			return fmt.Errorf("%w: path traversal attempt: %s", fault.ErrInvalidArgument, header.Name)
		}

		// Security: only extract regular files and directories.
		// Symlinks are skipped to prevent symlink attacks.
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, filesystem.DirPermissionsPrivate); err != nil {
				return fmt.Errorf("%w: failed to create directory: %w", fault.ErrFilesystemFailure, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), filesystem.DirPermissionsPrivate); err != nil {
				return fmt.Errorf("%w: failed to create parent directory: %w", fault.ErrFilesystemFailure, err)
			}

			//nolint:gosec // path has been verified above
			outFile, err := os.OpenFile(
				targetPath,
				os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
				(os.FileMode(header.Mode)&0o100)|filesystem.FilePermissionsPrivate,
			)
			if err != nil {
				return fmt.Errorf("%w: failed to create file: %w", fault.ErrFilesystemFailure, err)
			}

			if _, err := budget.limitedCopy(outFile, tarReader); err != nil {
				_ = outFile.Close()

				return fmt.Errorf("%w: failed to write file: %w", fault.ErrFilesystemFailure, err)
			}

			_ = outFile.Close()
		default:
		}
	}

	return nil
}

// extractAllFromZip extracts all files from a zip archive.
func (*HTTPRelease) extractAllFromZip(data []byte, destDir string) error {
	zipReader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("failed to create zip reader: %w", err)
	}

	budget := newExtractionBudget(maxExtractSize)

	for _, file := range zipReader.File {
		// Security: skip symlinks to prevent symlink attacks
		if file.Mode()&os.ModeSymlink != 0 {
			slog.Debug("skipping symlink in archive", "name", file.Name)

			continue
		}

		targetPath := filepath.Join(destDir, file.Name) //nolint:gosec // path is validated below
		if !isSubPath(destDir, targetPath) {
			return fmt.Errorf("%w: path traversal attempt: %s", fault.ErrInvalidArgument, file.Name)
		}

		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, filesystem.DirPermissionsPrivate); err != nil {
				return fmt.Errorf("%w: failed to create directory: %w", fault.ErrFilesystemFailure, err)
			}

			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), filesystem.DirPermissionsPrivate); err != nil {
			return fmt.Errorf("%w: failed to create parent directory: %w", fault.ErrFilesystemFailure, err)
		}

		reader, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file in zip: %w", err)
		}

		//nolint:gosec // path has been validated above
		outFile, err := os.OpenFile(
			targetPath,
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
			(file.Mode()&0o100)|filesystem.FilePermissionsPrivate,
		)
		if err != nil {
			_ = reader.Close()

			return fmt.Errorf("%w: failed to create file: %w", fault.ErrFilesystemFailure, err)
		}

		_, err = budget.limitedCopy(outFile, reader)
		_ = reader.Close()
		_ = outFile.Close()

		if err != nil {
			return fmt.Errorf("%w: failed to write file: %w", fault.ErrFilesystemFailure, err)
		}
	}

	return nil
}

// isSubPath checks if target is under base directory (prevents path traversal).
func isSubPath(base, target string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}

	return !filepath.IsAbs(rel) && rel != ".." && !startsWithDotDot(rel)
}

func startsWithDotDot(path string) bool {
	return len(path) >= 2 && path[0] == '.' && path[1] == '.' && (len(path) == 2 || path[2] == filepath.Separator)
}

// extractionBudget tracks remaining bytes allowed during extraction.
// Prevents decompression bomb attacks.
type extractionBudget struct {
	remaining int64
}

func newExtractionBudget(limit int64) *extractionBudget {
	return &extractionBudget{remaining: limit}
}

// limitedCopy copies from src to dst, respecting the extraction budget.
// Returns error if the budget would be exceeded.
func (b *extractionBudget) limitedCopy(dst io.Writer, src io.Reader) (int64, error) {
	limited := io.LimitReader(src, b.remaining+1) // +1 to detect overflow

	written, err := io.Copy(dst, limited)

	b.remaining -= written

	if b.remaining < 0 {
		return written, fmt.Errorf(
			"%w: archive exceeds maximum extraction size (%d bytes)",
			fault.ErrInvalidArgument,
			maxExtractSize,
		)
	}

	if err != nil {
		return written, fmt.Errorf("%w: %w", fault.ErrWriteFailure, err)
	}

	return written, nil
}
