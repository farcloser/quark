# Package version

## Purpose

Provides container image version checking by querying OCI registries for available tags and comparing them to current versions.

## Functionality

- **Registry tag listing** - Fetch all available tags for an image from any OCI registry
- **Semantic version parsing** - Extract and compare semantic versions (e.g., `1.2.3`, `2.10.2`)
- **Variant support** - Handle image variants (e.g., `alpine`, `distroless-static`)
- **Update detection** - Determine if newer versions are available
- **Digest retrieval** - Get digest for specific version tags
- **Auto-variant extraction** - Automatically extract variant suffix from version strings

## Public API

```go
type Checker struct { ... }
func NewChecker(username, password string, log zerolog.Logger) *Checker

// Version checking
func (c *Checker) CheckVersion(imageRef, currentVersion, variant string) (*Info, error)
func (c *Checker) GetTagDigest(imageRef string) (string, error)

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
- **Semantic versioning**: Parses and compares versions using custom semver logic
- **Variant filtering**: Only compares versions with matching variant suffixes
- **Tag enumeration**: Lists all tags and filters to valid semantic versions
- **Digest retrieval**: Fetches digest for specific version tags (immutable references)

## Version Format Support

Supports various version formats:
- Simple semver: `1.2.3`, `2.10.2`
- Variant suffixes: `2.10.2-alpine`, `1.0.0-distroless-static`
- Leading 'v': `v1.2.3` (automatically stripped)

## Variant Extraction

Variant is the part after the version number:
- `2.10.2-distroless-static` → version: `2.10.2`, variant: `distroless-static`
- `1.2.3-alpine` → version: `1.2.3`, variant: `alpine`
- `1.0.0` → version: `1.0.0`, variant: empty

## Version Comparison

Uses component-wise comparison:
- `1.2.3` < `1.2.4` (patch increment)
- `1.2.3` < `1.3.0` (minor increment)
- `1.9.9` < `2.0.0` (major increment)
- `1.10.0` > `1.9.0` (numeric comparison, not string)

## Dependencies

- External: `google/go-containerregistry` for OCI registry operations
- Internal: None (standalone module)

## Security Notes

- Supports authenticated registry access (username/password)
- Retrieves digests for immutable image references
- Tag-based version checking is informational only (tags can be moved)
