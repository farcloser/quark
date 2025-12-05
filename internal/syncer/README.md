# Package syncer

## Purpose

Provides container image synchronization between OCI registries with support for single-platform and multi-platform images.

## Functionality

- **Image synchronization** - Copy images from source registry to destination registry
- **Multi-platform support** - Automatic detection and handling of multi-platform image indices
- **Platform filtering** - Sync only specified platforms (caller-controlled)
- **Manifest list creation** - Automatically creates manifest lists for multi-platform syncs
- **Local digest computation** - Computes destination digests locally (not from registry) for security

## Public API

```go
// Syncer interface for image synchronization
type Syncer interface {
    Image(ctx context.Context, srcImage, dstImage name.Reference, platforms []string) (string, error)
}

// Constructor
func NewSyncer(srcClient, dstClient *registry.Client, log *slog.Logger) (Syncer, error)

// Errors
var (
    ErrNotFound           error  // Source image not found
    ErrGetPlatformDigests error  // Failed to get platform digests
    ErrCancelled          error  // Sync cancelled via context
    ErrFetchPlatform      error  // Failed to fetch platform image
    ErrCreateManifestList error  // Failed to create manifest list
    ErrCopyImage          error  // Failed to copy image
    ErrComputeDigest      error  // Failed to compute digest
)
```

## Design

- **Automatic platform detection**: Examines source image media type to determine single vs multi-platform
- **Platform-specific sync**: For multi-platform images, fetches each platform by digest from source
- **Security-first**: Uses source images fetched by digest to build destination manifest list

## Multi-Platform Sync Flow

1. Detect source is multi-platform image index (via MediaType)
2. Extract platform digests from source index
3. For each requested platform:
   - Fetch platform-specific image FROM SOURCE by digest
   - Collect v1.Image handle in platformImages map
4. Create and push manifest list at destination with collected platform images
5. Return locally-computed manifest list digest

## Single-Platform Sync Flow

1. Copy image from source to destination
2. Compute digest from source image (not fetched from destination)
3. Return computed digest

## Dependencies

- External: `google/go-containerregistry` for registry operations
- Internal: `internal2/registry` for registry client operations

## Security Considerations

- **Digest-based fetching**: Platform images fetched by digest from source ensures content integrity
- **Local digest computation**: Destination digest computed locally from pushed content, not retrieved from registry
- **Defense in depth**: Never fetches from destination to build manifest list - only uses source images
- **Context cancellation**: Checks context before each platform operation
