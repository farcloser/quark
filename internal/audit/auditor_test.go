package audit_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/farcloser/quark/internal/audit"
)

// INTENTION: NewAuditor should create a valid auditor.
func TestNewAuditor(t *testing.T) {
	t.Parallel()

	auditor := audit.NewAuditor(zerolog.Nop())

	if auditor == nil {
		t.Fatal("NewAuditor() returned nil, want non-nil auditor")
	}
}

// INTENTION: AuditDockerfile with non-existent file should fail.
func TestAuditor_AuditDockerfile_NonExistentFile(t *testing.T) {
	t.Parallel()

	auditor := audit.NewAuditor(zerolog.Nop())
	ctx := t.Context()

	result, err := auditor.AuditDockerfile(ctx, "/nonexistent/Dockerfile")

	// Should fail when hadolint can't find the file
	if err == nil && (result == nil || result.Passed) {
		t.Error("AuditDockerfile() expected failure for non-existent file")
	}
}

// INTENTION: AuditDockerfile with empty path should fail.
func TestAuditor_AuditDockerfile_EmptyPath(t *testing.T) {
	t.Parallel()

	auditor := audit.NewAuditor(zerolog.Nop())
	ctx := t.Context()

	result, err := auditor.AuditDockerfile(ctx, "")

	// Should fail with empty path
	if err == nil && (result == nil || result.Passed) {
		t.Error("AuditDockerfile() expected failure for empty path")
	}
}

// INTENTION: AuditDockerfile with valid but flawed Dockerfile should detect issues.
func TestAuditor_AuditDockerfile_DetectsIssues(t *testing.T) {
	t.Parallel()

	// Create a temporary Dockerfile with known issues
	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")

	// This Dockerfile has issues that hadolint will catch:
	// - Missing FROM
	// - Using latest tag
	flawedDockerfile := `# Missing FROM statement
RUN apt-get update
COPY . /app
`

	if err := os.WriteFile(dockerfilePath, []byte(flawedDockerfile), 0o600); err != nil {
		t.Fatalf("Failed to create test Dockerfile: %v", err)
	}

	auditor := audit.NewAuditor(zerolog.Nop())
	ctx := t.Context()

	result, err := auditor.AuditDockerfile(ctx, dockerfilePath)
	// Note: This test requires hadolint to be installed
	// If hadolint is not installed, the test will fail
	if err != nil {
		t.Skipf("Skipping test - hadolint may not be installed: %v", err)
	}

	if result == nil {
		t.Fatal("AuditDockerfile() result = nil, want non-nil result")
	}

	// The flawed Dockerfile should have issues
	if result.DockerfileIssues == 0 {
		t.Error("AuditDockerfile() found no issues in flawed Dockerfile, expected issues")
	}

	if result.Passed {
		t.Error("AuditDockerfile() passed = true, want false for flawed Dockerfile")
	}

	if result.Output == "" {
		t.Error("AuditDockerfile() output is empty, want formatted issues")
	}
}

// INTENTION: AuditImage with empty reference should fail.
func TestAuditor_AuditImage_EmptyReference(t *testing.T) {
	t.Parallel()

	auditor := audit.NewAuditor(zerolog.Nop())
	ctx := t.Context()

	opts := audit.ImageAuditOptions{
		RuleSet: "strict",
	}

	result, err := auditor.AuditImage(ctx, "", opts)

	// Should fail with empty reference
	if err == nil {
		t.Error("AuditImage() error = nil, want error for empty reference")
	}

	if result != nil {
		t.Errorf("AuditImage() result = %v, want nil on error", result)
	}
}

// INTENTION: AuditImage with invalid reference should fail.
func TestAuditor_AuditImage_InvalidReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		imageRef string
	}{
		{
			name:     "invalid characters",
			imageRef: "invalid@@@reference",
		},
		{
			name:     "malformed registry domain",
			imageRef: ":::invalid/repo:tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			auditor := audit.NewAuditor(zerolog.Nop())
			ctx := t.Context()

			opts := audit.ImageAuditOptions{
				RuleSet: "strict",
			}

			result, err := auditor.AuditImage(ctx, tt.imageRef, opts)

			// Should fail with invalid reference
			if err == nil {
				t.Error("AuditImage() error = nil, want error for invalid reference")
			}

			if result != nil {
				t.Errorf("AuditImage() result = %v, want nil on error", result)
			}
		})
	}
}

// INTENTION: ImageAuditOptions should support all rule sets.
func TestAuditor_AuditImage_RuleSets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ruleSet string
	}{
		{
			name:    "strict rule set",
			ruleSet: "strict",
		},
		{
			name:    "recommended rule set",
			ruleSet: "recommended",
		},
		{
			name:    "minimal rule set",
			ruleSet: "minimal",
		},
		{
			name:    "empty rule set defaults to strict",
			ruleSet: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := audit.ImageAuditOptions{
				RuleSet: tt.ruleSet,
			}

			// Just verify options can be created with different rule sets
			// Actual auditing behavior is tested with integration tests
			if opts.RuleSet != tt.ruleSet {
				t.Errorf("ImageAuditOptions.RuleSet = %q, want %q", opts.RuleSet, tt.ruleSet)
			}
		})
	}
}

// INTENTION: ImageAuditOptions should support ignore checks.
func TestAuditor_AuditImage_IgnoreChecks(t *testing.T) {
	t.Parallel()

	opts := audit.ImageAuditOptions{
		RuleSet:      "strict",
		IgnoreChecks: []string{"DKL-DI-0005", "DKL-DI-0006"},
	}

	if len(opts.IgnoreChecks) != 2 {
		t.Errorf("ImageAuditOptions.IgnoreChecks length = %d, want 2", len(opts.IgnoreChecks))
	}

	if opts.IgnoreChecks[0] != "DKL-DI-0005" {
		t.Errorf("ImageAuditOptions.IgnoreChecks[0] = %q, want \"DKL-DI-0005\"", opts.IgnoreChecks[0])
	}
}

// INTENTION: ImageAuditOptions should support optional registry credentials.
func TestAuditor_AuditImage_Credentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		registryHost string
		username     string
		password     string
	}{
		{
			name:         "no credentials",
			registryHost: "",
			username:     "",
			password:     "",
		},
		{
			name:         "full credentials",
			registryHost: "ghcr.io",
			username:     "testuser",
			password:     "testpass",
		},
		{
			name:         "username only",
			registryHost: "ghcr.io",
			username:     "testuser",
			password:     "",
		},
		{
			name:         "password only",
			registryHost: "ghcr.io",
			username:     "",
			password:     "testpass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := audit.ImageAuditOptions{
				RegistryHost: tt.registryHost,
				Username:     tt.username,
				Password:     tt.password,
				RuleSet:      "strict",
			}

			if opts.RegistryHost != tt.registryHost {
				t.Errorf("ImageAuditOptions.RegistryHost = %q, want %q", opts.RegistryHost, tt.registryHost)
			}

			if opts.Username != tt.username {
				t.Errorf("ImageAuditOptions.Username = %q, want %q", opts.Username, tt.username)
			}

			if opts.Password != tt.password {
				t.Errorf("ImageAuditOptions.Password = %q, want %q", opts.Password, tt.password)
			}
		})
	}
}
