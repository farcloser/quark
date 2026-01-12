# Package version

## Purpose

Provides container image version checking by querying OCI registries for available tags and comparing them to current versions.

## Functionality

- **Registry tag listing** - Fetch all available tags for an image from any OCI registry
- **Version parsing** - Extract prefix, version, and suffix from tags using regex
- **Prefix/suffix support** - Handle both prefixed (`trixie-2025-11-29`) and suffixed (`1.2.3-alpine`) versions
- **Auto-filter detection** - Automatically detect filter from current tag (suffix takes priority over prefix)
- **Semantic comparison** - Compare versions numerically, not lexicographically
- **Update detection** - Determine if newer versions are available
- **Digest retrieval** - Get digest for the latest version tag

## Public API

```go
type Checker struct { ... }
func NewChecker(username, password string, log *slog.Logger) *Checker

// Version checking - filter is auto-detected from imageRef's tag
func (c *Checker) CheckVersion(ctx context.Context, imageRef name.Reference) (*Info, error)

// Result type
type Info struct {
    CurrentVersion  string
    LatestVersion   string
    LatestDigest    string
    UpdateAvailable bool
}
```

## Design

- **Registry-agnostic**: Works with any OCI-compliant registry (Docker Hub, GHCR, etc.)
- **Auto-detection**: Filter automatically extracted from current tag's prefix or suffix
- **Exclusion patterns**: Filters out dev/test versions (nightly, dev, beta, alpha, rc, test, snapshot, builder)
- **Tag enumeration**: Lists all tags and filters to valid versions matching the detected filter

## Version Parsing

Tags are parsed using regex: `^([^0-9.-]*[.-])?v?([0-9.-]+)(.*)$`

| Component | Description | Example |
|-----------|-------------|---------|
| Prefix | Non-version chars before version | `trixie` in `trixie-2025-11-29` |
| Version | Digits, dots, hyphens (normalized to dots) | `2025.11.29` from `trixie-2025-11-29` |
| Suffix | Everything after version | `alpine` in `1.2.3-alpine` |

## Version Format Support

**Plain versions:**
- `1.2.3`, `v1.2.3`, `0.51.1`

**Suffixed versions (variants):**
- `1.2.3-alpine` → version: `1.2.3`, suffix: `alpine`
- `0.51.1-distroless-static` → version: `0.51.1`, suffix: `distroless-static`

**Prefixed versions (date-based or name-based):**
- `trixie-2025-11-29` → prefix: `trixie`, version: `2025.11.29`
- `bookworm-2025-05-01` → prefix: `bookworm`, version: `2025.05.01`
- `server-1.2.3` → prefix: `server`, version: `1.2.3`

**Combined prefix and suffix:**
- `server-v1.2.3-alpine` → prefix: `server`, version: `1.2.3`, suffix: `alpine`

## Filter Detection

Filter is auto-detected from the current tag:
1. If suffix is present, filter by suffix (e.g., `alpine`)
2. Otherwise, if prefix is present, filter by prefix (e.g., `trixie`)
3. If neither, match only plain versions (no prefix, no suffix)

## Version Comparison

Uses component-wise numeric comparison (hyphens normalized to dots):
- `1.2.3` < `1.2.4` (patch increment)
- `1.2.3` < `1.3.0` (minor increment)
- `1.10.0` > `1.9.0` (numeric, not lexicographic)
- `2025-11-29` < `2025-11-30` (date-based comparison works)

## Dependencies

- External: `google/go-containerregistry` for OCI registry operations
- Internal: None (standalone module)

## Security Notes

- Supports authenticated registry access (username/password)
- Retrieves digests for immutable image references
- Tag-based version checking is informational only (tags can be moved)
