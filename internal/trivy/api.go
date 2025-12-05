package trivy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/internal/tools"
	"github.com/farcloser/quark/internal/utilities"
)

// Severity levels for vulnerability findings.
const (
	// Unknown severity - unable to determine severity level.
	Unknown = "UNKNOWN"
	// Low severity - minimal impact, low priority.
	Low = "LOW"
	// Medium severity - moderate impact, should be addressed.
	Medium = "MEDIUM"
	// High severity - significant impact, address promptly.
	High = "HIGH"
	// Critical severity - severe impact, immediate action required.
	Critical = "CRITICAL"
)

//nolint:gochecknoglobals
var (
	// Trivy vulnerability scanner - pinned to v0.59.1 (commit 9aabfd2).
	trivyVersion = tools.Tool{
		Name:       "trivy",
		ImportPath: "github.com/aquasecurity/trivy/cmd/trivy",
		Version:    "9aabfd2", // v0.59.1 released 2025-02-05
	}
)

// Vulnerability represents a single vulnerability finding.
//
//nolint:tagliatelle
type Vulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
}

// Result represents a scan result for a specific target.
//
//nolint:tagliatelle
type Result struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

// ScanResult represents Trivy scan results.
//
//nolint:tagliatelle
type ScanResult struct {
	Results []Result `json:"Results"`
}

// Scanner provides vulnerability scanning for container images.
type Scanner interface {
	ScanImage(
		ctx context.Context,
		imageRef string,
		creds *utilities.RegistryCredentials,
		platforms []string,
	) (*ScanResult, error)
}

// NewScanner creates a new Trivy scanner.
func NewScanner(ctx context.Context, log *slog.Logger) (Scanner, error) {
	scanner := &trivyScanner{
		log: log.With("component", "trivy"),
	}

	var err error
	// Ensure trivy is installed
	scanner.trivyPath, err = tools.NewInstaller(log).Ensure(ctx, trivyVersion)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", utilities.ErrRequirementsFailed, err)
	}

	return scanner, nil
}
