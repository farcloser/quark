package version_test

import (
	"log/slog"
	"testing"

	"github.com/farcloser/quark/internal/a_deprecated/registry"
	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/internal/version"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// INTENTION: CheckVersion requires a tagged reference, digest-only references should fail.
func TestChecker_CheckVersion_RequiresTag(t *testing.T) {
	t.Parallel()

	// Digest-only reference should fail - CheckVersion requires a tag
	digestRef, err := reference.Parse("alpine@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	if err != nil {
		t.Fatalf("failed to parse digest reference: %v", err)
	}

	client := registry.NewClient(nil, discardLogger())
	checker := version.NewChecker(client, discardLogger())

	info, err := checker.CheckVersion(t.Context(), *digestRef)
	if err == nil {
		t.Fatal("CheckVersion() error = nil, want error for digest-only reference")
	}

	if info != nil {
		t.Errorf("CheckVersion() info = %v, want nil on error", info)
	}

	if !contains(err.Error(), "invalid argument") {
		t.Errorf("CheckVersion() error = %q, want error containing %q", err.Error(), "invalid argument")
	}
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
