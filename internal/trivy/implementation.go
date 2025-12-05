package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/farcloser/quark/internal/shared"
)

// scanMutex serializes scan operations to avoid Trivy database lock contention.
//
//nolint:gochecknoglobals
var scanMutex sync.Mutex

// Scanner wraps Trivy CLI operations.
type trivyScanner struct {
	log       *slog.Logger
	trivyPath string
}

// ScanImage scans an image for vulnerabilities across multiple platforms.
// Always scans both linux/amd64 and linux/arm64 platforms and aggregates results.
// If registry credentials are provided, logs in to the registry before scanning.
func (scanner *trivyScanner) ScanImage(
	ctx context.Context,
	imageRef string,
	creds *shared.RegistryCredentials,
	platforms []string,
) (*ScanResult, error) {
	// Login to registry if credentials provided
	if creds != nil && creds.Domain != "" && creds.Username != "" && creds.Token != "" {
		if err := scanner.registryLogin(ctx, creds.Domain, creds.Username, creds.Token); err != nil {
			return nil, err
		}
	}

	var aggregatedResult ScanResult

	for _, platform := range platforms {
		// Check context cancellation before each platform scan
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrCancelled, err)
		}

		result, err := scanner.scanPlatform(ctx, imageRef, platform)
		if err != nil {
			return nil, err
		}

		// Aggregate results from all platforms
		aggregatedResult.Results = append(aggregatedResult.Results, result.Results...)
	}

	return &aggregatedResult, nil
}

// scanPlatform scans a specific platform.
func (scanner *trivyScanner) scanPlatform(
	ctx context.Context,
	imageRef string,
	platform string,
) (*ScanResult, error) {
	scanner.log.DebugContext(ctx, "scanning platform", "platform", platform) //revive:disable-line:add-constant

	// Serialize scans to avoid Trivy database lock contention
	scanMutex.Lock()
	defer scanMutex.Unlock()

	// Build Trivy command with platform
	args := []string{
		"image",
		"--platform", platform,
		"--format", "json", // Always use JSON for parsing
		"--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
		"--quiet", // Suppress progress output
		imageRef,
	}

	//nolint:gosec // Command args are from trusted config
	cmd := exec.CommandContext(ctx, scanner.trivyPath, args...)

	// Initialize environment with parent variables
	cmd.Env = os.Environ()

	// Separate stdout and stderr to avoid mixing JSON with progress messages
	var stdout, stderr strings.Builder

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr != nil {
		// Trivy returns non-zero exit code when vulnerabilities are found
		// Only treat as error if we have no output to parse
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("%w (%s): %w\n%s", ErrUnableToScan, platform, runErr, stderr.String())
		}

		scanner.log.DebugContext(ctx, "trivy command completed with exit code",
			"platform", platform, "error", runErr) //revive:disable-line:add-constant
	}

	// Log stderr if present (progress messages, warnings)
	if stderr.Len() > 0 {
		scanner.log.DebugContext(
			ctx,
			"trivy stderr output",
			"platform", //revive:disable-line:add-constant
			platform,
			"stderr",
			stderr.String(),
		)
	}

	// Parse JSON output from stdout
	result := &ScanResult{}
	if err := json.Unmarshal([]byte(stdout.String()), result); err != nil {
		scanner.log.ErrorContext(
			ctx,
			"failed to parse trivy JSON output",
			"platform",
			platform,
			"stdout",
			stdout.String(),
			"stderr",
			stderr.String(),
		) //revive:disable-line:add-constant

		return nil, fmt.Errorf("%w (%s): %w", ErrParsingFailed, platform, err)
	}

	scanner.log.DebugContext(ctx, "platform scan complete", //revive:disable-line:add-constant
		"platform", platform, "vulnerabilities", countVulnerabilities(result))

	return result, nil
}

func countVulnerabilities(result *ScanResult) int {
	count := 0
	for _, scanResult := range result.Results {
		count += len(scanResult.Vulnerabilities)
	}

	return count
}

// registryLogin logs in to a registry using trivy registry login.
// This stores credentials in Docker's config (~/.docker/config.json) and keeps
// them out of the process list. Credentials are only sent to the specific registry.
func (scanner *trivyScanner) registryLogin(ctx context.Context, registryHost, username, password string) error {
	scanner.log.DebugContext(ctx, "registryLogin: start", "registry", registryHost) //revive:disable-line:add-constant

	// Use --password-stdin to avoid password in process list
	//nolint:gosec
	cmd := exec.CommandContext(
		ctx,
		scanner.trivyPath,
		"registry", //revive:disable-line:add-constant
		"login",
		registryHost,
		"--username",
		username,
		"--password-stdin",
	)
	cmd.Stdin = strings.NewReader(password)

	// Capture output for error reporting
	output, err := cmd.CombinedOutput()
	if err != nil {
		scanner.log.DebugContext(
			ctx,
			"registryLogin: fail",
			"registry", //revive:disable-line:add-constant
			registryHost,
		) //revive:disable-line:add-constant

		return fmt.Errorf("%w: %w\n%s", ErrUnableToLogin, err, output)
	}

	scanner.log.DebugContext(ctx, "registryLogin: success", "registry", registryHost) //revive:disable-line:add-constant

	return nil
}
