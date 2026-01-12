# Package godolint

## Purpose

Provides Dockerfile linting using the godolint SDK to detect best practice violations and potential issues.

## Functionality

- **Dockerfile linting** - Scan Dockerfiles for best practice violations, security issues, and potential bugs
- **Severity levels** - Violations categorized by severity (Error, Warning, Info, Style)
- **SDK integration** - Uses godolint SDK directly (no external binary dependency)

## Public API

```go
// Scanner interface for Dockerfile linting
type Scanner interface {
    ScanDockerfile(ctx context.Context, dockerfilePath string) (*Result, error)
}

// Constructor
func NewScanner(log *slog.Logger) Scanner

// Types (aliases from godolint SDK)
type Violation = sdk.Violation
type Severity = sdk.Severity

// Severity constants
const (
    SeverityError   = sdk.SeverityError
    SeverityWarning = sdk.SeverityWarning
    SeverityInfo    = sdk.SeverityInfo
    SeverityStyle   = sdk.SeverityStyle
)

// Result type
type Result struct {
    Violations []Violation
}
```

## Design

- **SDK integration**: Uses `github.com/farcloser/godolint/sdk` directly
- **Type aliases**: Re-exports SDK types to reduce coupling
- **File-based scanning**: Reads Dockerfile from disk and passes content to SDK
- **Structured output**: Returns violations with rule codes, messages, and line numbers

## Dependencies

- External: `github.com/farcloser/godolint/sdk` for linting logic
- Internal: None

## Security Considerations

- **Local files only**: Only reads Dockerfiles from local filesystem
- **No network access**: Linting happens entirely locally
