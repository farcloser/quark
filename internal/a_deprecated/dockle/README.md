# Package dockle

## Purpose

Provides container image linting using Dockle to check Dockerfile best practices and security issues.

## Functionality

- **Image linting** - Scan container images for Dockerfile best practices violations
- **Registry authentication** - Supports private registry authentication via environment variables

## Public API

```go
// Scanner interface for image linting
type Scanner interface {
    ScanImage(ctx context.Context, imageRef string, registryHost string, username string, password string) (*ScanResult, error)
}

// Constructor
func NewScanner(log *slog.Logger) (Scanner, error)

// Types
type Detail struct {
    Code   string   `json:"code"`
    Title  string   `json:"title"`
    Level  string   `json:"level"`
    Alerts []string `json:"alerts"`
}

type ScanResult struct {
    Details []Detail `json:"details"`
}
```

## Design

- **Dockle CLI wrapper**: Executes Dockle as subprocess with JSON output format
- **Automatic tool installation**: Uses internal2/tools to ensure Dockle is available
- **JSON parsing**: Parses Dockle's JSON output into structured Go types
- **Secure credential handling**: Uses environment variables (DOCKLE_AUTH_URL, DOCKLE_USERNAME, DOCKLE_PASSWORD) instead of CLI args

## Dependencies

- External: Dockle CLI tool (auto-installed via internal2/tools)
- Internal: `internal2/tools` for Dockle installation management

## Security Considerations

- **Credential security**: Registry credentials passed via environment variables, not CLI args (avoids exposure in process list)
- **Scoped authentication**: DOCKLE_AUTH_URL scopes credentials to the specific registry
