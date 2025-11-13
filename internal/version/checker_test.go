package version_test

import (
	"testing"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/version"
)

// INTENTION: Invalid image references should fail at parse stage before registry access.
func TestChecker_CheckVersion_InvalidImageReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		imageRef       string
		currentVersion string
		variant        string
		wantErrMsg     string
	}{
		{
			name:           "empty image reference",
			imageRef:       "",
			currentVersion: "1.0.0",
			variant:        "",
			wantErrMsg:     "failed to parse repository",
		},
		{
			name:           "invalid characters in reference",
			imageRef:       "invalid@@@image",
			currentVersion: "1.0.0",
			variant:        "",
			wantErrMsg:     "failed to parse repository",
		},
		{
			name:           "reference with digest should fail for repository parse",
			imageRef:       "alpine@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			currentVersion: "1.0.0",
			variant:        "",
			wantErrMsg:     "failed to parse repository",
		},
		{
			name:           "malformed registry domain",
			imageRef:       ":::invalid/repo",
			currentVersion: "1.0.0",
			variant:        "",
			wantErrMsg:     "failed to parse repository",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checker := version.NewChecker("", "", zerolog.Nop())
			info, err := checker.CheckVersion(tt.imageRef, tt.currentVersion, tt.variant)

			if err == nil {
				t.Fatal("CheckVersion() error = nil, want error")
			}

			if info != nil {
				t.Errorf("CheckVersion() info = %v, want nil on error", info)
			}

			// Verify error message contains expected substring
			if err.Error() == "" || !contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("CheckVersion() error = %q, want error containing %q", err.Error(), tt.wantErrMsg)
			}
		})
	}
}

// INTENTION: Invalid image references should fail at parse stage before registry access.
func TestChecker_GetTagDigest_InvalidImageReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		imageRef   string
		wantErrMsg string
	}{
		{
			name:       "empty image reference",
			imageRef:   "",
			wantErrMsg: "failed to parse image reference",
		},
		{
			name:       "invalid characters in reference",
			imageRef:   "invalid@@@image",
			wantErrMsg: "failed to parse image reference",
		},
		{
			name:       "malformed digest",
			imageRef:   "alpine@notadigest",
			wantErrMsg: "failed to parse image reference",
		},
		{
			name:       "malformed registry domain",
			imageRef:   ":::invalid/repo:tag",
			wantErrMsg: "failed to parse image reference",
		},
		{
			name:       "tag with invalid characters",
			imageRef:   "alpine:invalid@@@tag",
			wantErrMsg: "failed to parse image reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checker := version.NewChecker("", "", zerolog.Nop())
			digest, err := checker.GetTagDigest(tt.imageRef)

			if err == nil {
				t.Fatal("GetTagDigest() error = nil, want error")
			}

			if digest != "" {
				t.Errorf("GetTagDigest() digest = %q, want empty string on error", digest)
			}

			// Verify error message contains expected substring
			if err.Error() == "" || !contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("GetTagDigest() error = %q, want error containing %q", err.Error(), tt.wantErrMsg)
			}
		})
	}
}

// INTENTION: Checker creation should accept optional credentials.
func TestNewChecker(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "no credentials",
			username: "",
			password: "",
		},
		{
			name:     "with credentials",
			username: "testuser",
			password: "testpass",
		},
		{
			name:     "username only",
			username: "testuser",
			password: "",
		},
		{
			name:     "password only",
			username: "",
			password: "testpass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checker := version.NewChecker(tt.username, tt.password, zerolog.Nop())

			if checker == nil {
				t.Fatal("NewChecker() returned nil, want non-nil checker")
			}
		})
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
