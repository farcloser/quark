# Package reference

## Purpose

Provides parsing and manipulation of OCI container image references, supporting tags, digests, registries, and repository paths.

## Functionality

- **Reference parsing** - Parse image reference strings into structured components
- **Component extraction** - Extract domain, path, tag, and digest from references
- **Name formatting** - Generate full names and familiar (shortened) names
- **Pattern matching** - Check if references match familiar patterns
- **Container naming** - Generate suggested container names based on image references
- **Digest support** - Parse and handle both full and short digest formats
- **Tag normalization** - Automatically applies "latest" tag when no tag specified

## Public API

```go
type ImageReference struct {
    Protocol    Protocol
    Digest      digest.Digest
    Tag         string
    ExplicitTag string // Tag explicitly specified in input (empty if omitted)
    Path        string
    Domain      string
}

// Parsing
func Parse(rawRef string) (*ImageReference, error)

// Methods
func (ir *ImageReference) Name() string                              // Full name (domain/path)
func (ir *ImageReference) FamiliarName() string                      // Shortened name
func (ir *ImageReference) FamiliarMatch(pattern string) (bool, error) // Pattern matching
func (ir *ImageReference) String() string                            // String representation
func (ir *ImageReference) SuggestContainerName(suffix string) string // Generate container name

// Exported error types
var (
    ErrInvalidImageReference error
    ErrInvalidPattern        error
)
```

## Design

- **Reference normalization**: Uses `distribution/reference` library for standardized parsing
- **Tag defaulting**: Automatically adds "latest" tag via `TagNameOnly` when no tag specified
- **Digest detection**: Tries parsing as digest first (with and without "sha256:" prefix)
- **Protocol support**: Special handling for non-registry protocols (via Protocol field)
- **Familiar names**: Follows Docker conventions for shortened display names
- **Container naming**: Generates safe container names from image references (base name + suffix)

## Reference Format Support

Supported reference formats:
- `registry.example.com/namespace/image:tag`
- `namespace/image:tag` (uses default registry)
- `image:tag` (uses default registry and namespace)
- `image` (adds "latest" tag automatically)
- `registry.example.com/namespace/image@sha256:abc123...`
- `sha256:abc123...` (digest-only reference)
- `abc123...` (short digest, automatically prefixed with "sha256:")

## Dependencies

- External: `distribution/reference` for OCI reference parsing, `opencontainers/go-digest` for digest handling
- Internal: None (standalone module)

## Security Considerations

- **Input validation**: All references validated and normalized via `distribution/reference`
- **Digest verification**: Full digest format support for content-addressable pulls
- **No string injection**: Uses type-safe digest and reference types, not string concatenation
