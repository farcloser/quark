# Package tools

## Purpose

Provides automatic installation and version management for external CLI tools required by quark (trivy, dockle).

## Functionality

- **Auto-installation** - Automatically installs missing tools using `go install`
- **Commit hash pinning** - Tools pinned to specific git commits for immutability and reproducibility
- **Session caching** - Tracks installed tools per session to avoid redundant checks
- **PATH verification** - Ensures tools are accessible after installation

## Public API

```go
type Tool struct {
    Name       string // Binary name (e.g., "trivy")
    ImportPath string // Go import path (e.g., "github.com/aquasecurity/trivy/cmd/trivy")
    Version    string // Commit hash for immutable pinning (e.g., "9aabfd2")
}

type Installer struct { ... }
func NewInstaller(log *slog.Logger) *Installer

// Installation operations
func (i *Installer) Ensure(tool Tool) (string, error)
```

Note: Tool definitions (trivy, dockle) are defined in their respective packages (`internal2/trivy`, `internal2/dockle`), not in this package.

## Design

- **Immutable versioning**: Uses git commit SHAs instead of tags (tags can be moved/deleted)
- **Reproducible builds**: Same commit always produces same binary
- **Go module integration**: Uses `go install` for automatic compilation and installation
- **Thread-safe**: Mutex-protected installation tracking
- **GOPATH/GOBIN aware**: Respects user's Go environment configuration

## Installation Strategy

Tools are installed via `go install <import-path>@<commit-hash>`:

1. Check if tool already verified in current session (fast path)
2. Check if tool exists at expected path (GOBIN or GOPATH/bin)
3. If not found, run `go install` with pinned commit hash
4. Verify installation succeeded
5. Cache result for session

## Version Pinning

Commit hashes provide cryptographic immutability:
- Git commit SHA-256 hashes are permanent and cannot be changed
- Go modules automatically convert to pseudo-versions (e.g., `v0.0.0-20250205xxxxxx-9aabfd2`)
- No risk of tag deletion or movement breaking builds

## Updating Tools

To update a tool version:
1. Find the release on GitHub
2. Get the commit hash for that release tag
3. Update the `Version` field in the Tool definition (in the consuming package)
4. Test with `go install <import-path>@<new-commit-hash>`

## Dependencies

- External: Uses `go install` command (requires Go toolchain)
- Internal: None (standalone module)

## Security Notes

- Tools are compiled from source (not downloading pre-built binaries)
- Source code is controlled by commit hash pinning
- No supply chain attacks via moved/deleted tags
