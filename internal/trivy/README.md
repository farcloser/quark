# Package trivy

## Purpose

Provides container image vulnerability scanning using Trivy with support for severity filtering and multiple output formats.

## Functionality

- **Vulnerability scanning** - Scan container images for known CVEs and security issues
- **Multi-platform scanning** - Automatically scans both linux/amd64 and linux/arm64 platforms
- **Severity filtering** - Filter results by severity levels (UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)
- **Multiple output formats** - Support for table, JSON, and SARIF output formats
- **Registry authentication** - Automatic registry login for private image scanning
- **Threshold checking** - Verify if scan results meet severity thresholds

## Public API

```go
type Scanner struct { ... }
func NewScanner(log zerolog.Logger) *Scanner

// Scanning operations
func (s *Scanner) ScanImage(imageRef string, severities []Severity, format, registryHost, username, password string) (*ScanResult, error)
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
- **Multi-platform by default**: Scans both amd64 and arm64, aggregates results
- **JSON parsing**: Parses Trivy's JSON output into structured Go types
- **Registry credential injection**: Uses `trivy image --username/--password` for private registries

## Supported Formats

- **table**: Human-readable table format (default Trivy output)
- **json**: Structured JSON format for programmatic processing
- **sarif**: SARIF format for integration with security tools (GitHub Security, etc.)

## Dependencies

- External: Trivy CLI tool (auto-installed via internal/tools)
- Internal: `internal/tools` for Trivy installation management

## Security Notes

- Always scans with specific severity levels (never defaults)
- Registry credentials passed via CLI flags (not environment variables)
- Supports scanning by digest for immutable image references
