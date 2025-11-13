# Package trivy

## Purpose

Provides container image vulnerability scanning using Trivy with support for severity filtering and multiple output formats.

## Functionality

- **Vulnerability scanning** - Scan container images for known CVEs and security issues
- **Multi-platform scanning** - Automatically scans both linux/amd64 and linux/arm64 platforms
- **Severity filtering** - Filter results by severity levels (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)
- **Multiple output formats** - Support for table and JSON output formats
- **Registry authentication** - Automatic registry login for private image scanning
- **Threshold checking** - Verify if scan results meet severity thresholds

## Public API

```go
type Scanner struct { ... }
func NewScanner(log zerolog.Logger) *Scanner

// Scanning operations (all accept context.Context for cancellation)
func (s *Scanner) ScanImage(ctx context.Context, imageRef string, severities []Severity, outputFormat string, registryHost string, username string, password string) (*ScanResult, error)
func (s *Scanner) FormatOutput(result *ScanResult, format string) (string, error)
func (s *Scanner) CheckThreshold(result *ScanResult, severities []Severity) bool

// Types
type Severity string // UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL

type Vulnerability struct {
    VulnerabilityID  string
    PkgName          string
    InstalledVersion string
    FixedVersion     string
    Severity         string
    Title            string
}

type Result struct {
    Target          string
    Vulnerabilities []Vulnerability
}

type ScanResult struct {
    Results []Result
}
```

## Design

- **Trivy CLI wrapper**: Executes Trivy as subprocess with appropriate flags
- **Automatic tool installation**: Uses internal/tools to ensure Trivy is available
- **Multi-platform by default**: Scans both amd64 and arm64 (hardcoded), aggregates results
- **JSON parsing**: Parses Trivy's JSON output into structured Go types
- **Secure credential handling**: Uses `trivy registry login` with `--password-stdin`

## Supported Formats

- **table**: Human-readable table format with severity, CVE ID, package info
- **json**: Structured JSON format for programmatic processing

Note: Trivy scans always use JSON format internally for parsing, then convert to requested format.

## Dependencies

- External: Trivy CLI tool (auto-installed via internal/tools)
- Internal: `internal/tools` for Trivy installation management

## Security Considerations

- **Password security**: Registry passwords passed via stdin (not CLI args or environment)
- **Registry login**: Uses `trivy registry login` which stores credentials in Docker config (~/.docker/config.json)
- **Severity filtering**: Always requires explicit severity levels (no defaults)
- **Digest support**: Supports scanning by digest for immutable image references
- **Separate streams**: stdout/stderr separated to avoid mixing JSON with progress messages
