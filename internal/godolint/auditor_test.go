package godolint_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/farcloser/quark/dev/filesystem"
	"github.com/farcloser/quark/internal/godolint"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// INTENTION: NewScanner should create a valid scanner.
func TestNewScanner(t *testing.T) {
	t.Parallel()

	scanner := godolint.NewScanner(discardLogger())

	if scanner == nil {
		t.Fatal("NewScanner() returned nil, want non-nil scanner")
	}
}

// INTENTION: ScanDockerfile with non-existent file should fail.
func TestScanner_ScanDockerfile_NonExistentFile(t *testing.T) {
	t.Parallel()

	scanner := godolint.NewScanner(discardLogger())
	ctx := t.Context()

	_, err := scanner.ScanDockerfile(ctx, "/nonexistent/Dockerfile")

	// Should fail when godolint can't find the file
	if err == nil {
		t.Error("ScanDockerfile() expected error for non-existent file")
	}
}

// INTENTION: ScanDockerfile with empty path should fail.
func TestScanner_ScanDockerfile_EmptyPath(t *testing.T) {
	t.Parallel()

	scanner := godolint.NewScanner(discardLogger())
	ctx := t.Context()

	_, err := scanner.ScanDockerfile(ctx, "")

	// Should fail with empty path
	if err == nil {
		t.Error("ScanDockerfile() expected error for empty path")
	}
}

// INTENTION: ScanDockerfile with valid but flawed Dockerfile should detect issues.
func TestScanner_ScanDockerfile_DetectsIssues(t *testing.T) {
	t.Parallel()

	// Create a temporary Dockerfile with known issues
	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")

	// This Dockerfile has issues that godolint will catch:
	// - DL3007: Using latest tag
	// - DL3008: Pin versions in apt-get install
	// - DL3009: Delete apt-get lists after installing
	// - DL3057: Missing HEALTHCHECK
	flawedDockerfile := `FROM debian:latest
RUN apt-get update && apt-get install -y curl
COPY . /app
`

	if err := os.WriteFile(dockerfilePath, []byte(flawedDockerfile), filesystem.FilePermissionsPrivate); err != nil {
		t.Fatalf("Failed to create test Dockerfile: %v", err)
	}

	scanner := godolint.NewScanner(discardLogger())
	ctx := t.Context()

	result, err := scanner.ScanDockerfile(ctx, dockerfilePath)
	if err != nil {
		t.Fatalf("ScanDockerfile() error = %v, want nil", err)
	}

	if result == nil {
		t.Fatal("ScanDockerfile() result = nil, want non-nil result")
	}

	// The flawed Dockerfile should have violations
	if len(result.Violations) == 0 {
		t.Error("ScanDockerfile() found no violations in flawed Dockerfile, expected violations")
	}
}
