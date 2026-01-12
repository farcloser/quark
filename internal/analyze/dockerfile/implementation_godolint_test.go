package dockerfile_test

import (
	"log/slog"
	"testing"

	"github.com/farcloser/quark/internal/analyze/dockerfile"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// INTENTION: NewScanner should create a valid scanner.
func TestNewScanner(t *testing.T) {
	t.Parallel()

	scanner := dockerfile.NewScanner(discardLogger())

	if scanner == nil {
		t.Fatal("NewScanner() returned nil, want non-nil scanner")
	}
}

// INTENTION: Scan with empty content should return an error (no instructions).
func TestScanner_ScanDockerfile_EmptyContent(t *testing.T) {
	t.Parallel()

	scanner := dockerfile.NewScanner(discardLogger())
	ctx := t.Context()

	_, err := scanner.Scan(ctx, []byte{})

	// Empty Dockerfile has no instructions, godolint returns an error
	if err == nil {
		t.Error("Scan() expected error for empty content, got nil")
	}
}

// INTENTION: Scan with nil content should return an error (no instructions).
func TestScanner_ScanDockerfile_NilContent(t *testing.T) {
	t.Parallel()

	scanner := dockerfile.NewScanner(discardLogger())
	ctx := t.Context()

	_, err := scanner.Scan(ctx, nil)

	// Nil content has no instructions, godolint returns an error
	if err == nil {
		t.Error("Scan() expected error for nil content, got nil")
	}
}

// INTENTION: Scan with valid but flawed Dockerfile should detect issues.
func TestScanner_ScanDockerfile_DetectsIssues(t *testing.T) {
	t.Parallel()

	// This Dockerfile has issues that godolint will catch:
	// - DL3007: Using latest tag
	// - DL3008: Pin versions in apt-get install
	// - DL3009: Delete apt-get lists after installing
	// - DL3057: Missing HEALTHCHECK
	flawedDockerfile := []byte(`FROM debian:latest
RUN apt-get update && apt-get install -y curl
COPY . /app
`)

	scanner := dockerfile.NewScanner(discardLogger())
	ctx := t.Context()

	result, err := scanner.Scan(ctx, flawedDockerfile)
	if err != nil {
		t.Fatalf("Scan() error = %v, want nil", err)
	}

	if result == nil {
		t.Fatal("Scan() result = nil, want non-nil result")
	}

	// The flawed Dockerfile should have violations
	if len(result.Violations) == 0 {
		t.Error("Scan() found no violations in flawed Dockerfile, expected violations")
	}
}
