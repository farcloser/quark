package trivy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/dev/tools"
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
	trivyTool = tools.GoTool{
		Name:       "trivy",
		ImportPath: "github.com/aquasecurity/trivy/cmd/trivy",
		Version:    "9aabfd2", // v0.59.1 released 2025-02-05
	}
)

// PkgIdentifier contains package identification for VEX matching.
//
//nolint:tagliatelle
type PkgIdentifier struct {
	PURL string `json:"PURL"`
}

// Vulnerability represents a single vulnerability finding from Trivy output.
//
//nolint:tagliatelle
type Vulnerability struct {
	VulnerabilityID  string        `json:"VulnerabilityID"`
	PkgName          string        `json:"PkgName"`
	InstalledVersion string        `json:"InstalledVersion"`
	FixedVersion     string        `json:"FixedVersion"`
	Severity         string        `json:"Severity"`
	Title            string        `json:"Title"`
	PkgIdentifier    PkgIdentifier `json:"PkgIdentifier"`
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

// ScanOptions configures scan behavior.
type ScanOptions struct {
	// ShowSuppressed logs vulnerabilities that were filtered by VEX attestations.
	ShowSuppressed bool
	// VEXPaths contains paths to VEX files to apply during scanning.
	// These are passed to Trivy via --vex flags.
	VEXPaths []string
}

// Scanner provides vulnerability scanning for container images.
type Scanner interface {
	ScanImage(
		ctx context.Context,
		imageRef string,
		platforms []string,
		opts *ScanOptions,
	) (*ScanResult, error)
}

// NewScanner creates a new Trivy scanner.
func NewScanner(ctx context.Context, log *slog.Logger) (Scanner, error) {
	scanner := &trivyScanner{
		log: log.With("component", "trivy"),
	}

	var err error
	// Ensure trivy is installed
	scanner.trivyPath, err = tools.NewGoInstaller(log, trivyTool).Ensure(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrMissingRequirements, err)
	}

	return scanner, nil
}
