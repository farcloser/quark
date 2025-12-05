# Package trivy

## Purpose

Provides container image vulnerability scanning using Trivy with multi-platform support and result aggregation.

## Functionality

- **Vulnerability scanning** - Scan container images for known CVEs and security issues
- **Multi-platform scanning** - Scans specified platforms and aggregates results
- **Registry authentication** - Automatic registry login for private image scanning
- **Severity levels** - Results include severity (Unknown, Low, Medium, High, Critical)

## Public API

```go
// Scanner interface for vulnerability scanning
type Scanner interface {
    ScanImage(ctx context.Context, imageRef, registryHost, username, password string, platforms []string) (*ScanResult, error)
}

// Constructor
func NewScanner(log *slog.Logger) (Scanner, error)

// Severity constants
const (
    Unknown  = "UNKNOWN"
    Low      = "LOW"
    Medium   = "MEDIUM"
    High     = "HIGH"
    Critical = "CRITICAL"
)

// Types
type Vulnerability struct {
    VulnerabilityID  string `json:"VulnerabilityID"`
    PkgName          string `json:"PkgName"`
    InstalledVersion string `json:"InstalledVersion"`
    FixedVersion     string `json:"FixedVersion"`
    Severity         string `json:"Severity"`
    Title            string `json:"Title"`
}

type Result struct {
    Target          string          `json:"Target"`
    Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type ScanResult struct {
    Results []Result `json:"Results"`
}

// Errors
var (
    ErrRequirementsFailed error  // Trivy installation failed
    ErrParsingFailed      error  // JSON output parsing failed
    ErrLoginFailed        error  // Registry login failed
    ErrScanFailed         error  // Scan operation failed
)
```

## Design

- **Trivy CLI wrapper**: Executes Trivy as subprocess with JSON output format
- **Automatic tool installation**: Uses internal2/tools to ensure Trivy is available (pinned to v0.59.1)
- **Platform iteration**: Scans each platform sequentially, aggregates all results
- **JSON parsing**: Parses Trivy's JSON output into structured Go types
- **Secure credential handling**: Uses `trivy registry login` with `--password-stdin`
- **Concurrency safety**: Global mutex prevents Trivy database lock contention

## Scan Flow

1. If credentials provided, login to registry via `trivy registry login`
2. For each requested platform:
   - Acquire scan mutex (prevents database contention)
   - Execute `trivy image --platform <platform> --format json`
   - Parse JSON output
   - Release mutex
3. Aggregate results from all platforms
4. Return combined ScanResult

## Dependencies

- External: Trivy CLI tool (auto-installed via internal2/tools at commit 9aabfd2 / v0.59.1)
- Internal: `internal2/tools` for Trivy installation management

## Security Considerations

- **Password security**: Registry passwords passed via stdin (not CLI args or environment)
- **Registry login**: Uses `trivy registry login` which stores credentials in Docker config
- **Digest support**: Supports scanning by digest for immutable image references
- **Separate streams**: stdout/stderr separated to avoid mixing JSON with progress messages
- **Non-zero exit codes**: Handled correctly (vulnerabilities found is not an error)
