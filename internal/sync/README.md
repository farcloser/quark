# Package sync

## Purpose

Provides container image synchronization between OCI registries with support for single-platform and multi-platform images.

## Functionality

- **Image synchronization** - Copy images from source registry to destination registry
- **Multi-platform support** - Automatic detection and handling of multi-platform image indices
- **Platform filtering** - Syncs only linux/amd64 and linux/arm64 platforms (hardcoded)
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
- **Platform-specific sync**: For multi-platform images, fetches each platform by digest from source, then creates manifest list at destination
- **Security-first**: Uses source images fetched by digest to build destination manifest list (defense against registry tampering)
- **Black script compatibility**: Matches the approach used in `black/scripts/sync-images.sh`

## Multi-Platform Sync Flow

1. Detect source is multi-platform image index (via MediaType)
2. Extract platform digests from source index
3. For each supported platform (linux/amd64, linux/arm64):
   - Fetch platform-specific image FROM SOURCE by digest
   - Collect v1.Image handle in platformImages map
4. Create and push manifest list at destination with collected platform images
5. Return locally-computed manifest list digest

**Security note**: Platform images are fetched by digest from SOURCE (not destination), ensuring the manifest list is built from verified content.

## Dependencies

- External: `google/go-containerregistry` for registry operations
- Internal: `internal/registry` for registry client operations

## Security Considerations

- **Digest-based fetching**: Platform images fetched by digest from source ensures content integrity
- **Local digest computation**: Destination digest computed locally from pushed content, not retrieved from registry
- **Defense in depth**: Never fetches from destination to build manifest list - only uses source images
- **Platform filtering**: Prevents syncing unsupported architectures (only linux/amd64 and linux/arm64)
