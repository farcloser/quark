# Package sync

## Purpose

Provides container image synchronization between OCI registries with support for single-platform and multi-platform images.

## Functionality

- **Image synchronization** - Copy images from source registry to destination registry
- **Multi-platform support** - Automatic detection and handling of multi-platform image indices
- **Platform filtering** - Syncs only linux/amd64 and linux/arm64 platforms (configurable)
- **Manifest list creation** - Automatically creates manifest lists for multi-platform syncs
- **Local digest computation** - Computes destination digests locally (not from registry) for security

## Public API

```go
type Syncer struct { ... }
func NewSyncer(srcClient, dstClient *registry.Client, log zerolog.Logger) *Syncer

// Sync operations
func (s *Syncer) SyncImage(srcImage, dstImage string) (string, error)
func (s *Syncer) CheckExists(imageRef string) (bool, error)
```

## Design

- **Automatic platform detection**: Examines source image media type to determine single vs multi-platform
- **Platform-specific copying**: For multi-platform images, copies each platform separately then creates manifest list
- **Security-first**: Returns locally-computed digest, not registry-provided digest (defense in depth)
- **Black script compatibility**: Matches the approach used in `black/scripts/sync-images.sh`

## Multi-Platform Sync Flow

1. Detect source is multi-platform image index
2. Extract platform digests from source
3. For each supported platform (linux/amd64, linux/arm64):
   - Copy platform-specific image to destination with platform suffix (e.g., `image:tag-amd64`)
   - Fetch the pushed image to get v1.Image handle
4. Create and push manifest list at destination referencing all platform images
5. Return locally-computed manifest list digest

## Dependencies

- External: `google/go-containerregistry` for registry operations
- Internal: `internal/registry` for registry client operations

## Security Notes

- Destination digest is computed locally from pushed content, not retrieved from registry
- This provides defense in depth against compromised registries
- Platform filtering prevents syncing unsupported architectures
