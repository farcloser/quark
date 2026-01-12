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
// Registry authentication is handled by the registry Execute() action via docker login,
// which stores credentials in Docker's config for trivy to use automatically.
func (scanner *trivyScanner) ScanImage(
	ctx context.Context,
	imageRef string,
	platforms []string,
	opts *ScanOptions,
) (*ScanResult, error) {
	var aggregatedResult ScanResult

	for _, platform := range platforms {
		// Check context cancellation before each platform scan
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("scan cancelled: %w", err)
		}

		result, err := scanner.scanPlatform(ctx, imageRef, platform, opts)
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
	opts *ScanOptions,
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
	}

	// Add optional flags
	if opts != nil {
		if opts.ShowSuppressed {
			args = append(args, "--show-suppressed")
		}

		// Add VEX files if provided
		for _, vexPath := range opts.VEXPaths {
			args = append(args, "--vex", vexPath)
		}
	}

	args = append(args, imageRef)

	scanner.log.DebugContext(ctx, "executing trivy command",
		"command", scanner.trivyPath+" "+strings.Join(args, " "))

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

	// Filter out false positives
	filterFalsePositives(result)

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

// filterFalsePositives removes known false positive vulnerabilities from scan results.
// Currently filters kernel CVEs reported against linux-libc-dev, which contains only
// header files and cannot be affected by kernel runtime bugs.
func filterFalsePositives(result *ScanResult) {
	for idx := range result.Results {
		filtered := result.Results[idx].Vulnerabilities[:0]

		for _, vuln := range result.Results[idx].Vulnerabilities {
			if !isKernelFalsePositive(vuln) {
				filtered = append(filtered, vuln)
			}
		}

		result.Results[idx].Vulnerabilities = filtered
	}
}

// isKernelFalsePositive returns true if the vulnerability is a kernel bug reported
// against linux-libc-dev. The linux-libc-dev package contains only C header files
// defining kernel interfaces - no executable code. Kernel CVEs (identified by titles
// starting with "kernel:") cannot affect header-only packages.
func isKernelFalsePositive(vuln Vulnerability) bool {
	return vuln.PkgName == "linux-libc-dev" && strings.HasPrefix(vuln.Title, "kernel:")
}
