# Package registry

## Purpose

Provides OCI-compliant container registry client operations for pulling, pushing, and synchronizing container images.

## Functionality

- **Image retrieval** - Fetch image descriptors and metadata from registries
- **Image copying** - Transfer images between registries (single-platform and multi-platform)
- **Manifest list management** - Create and push multi-platform manifest lists
- **Digest operations** - Extract and verify image digests
- **Existence checks** - Verify if images exist in registries (with proper 404 handling)

## Public API

```go
type Client struct { ... }
func NewClient(host, username, password string, log zerolog.Logger) *Client

// Retrieval operations
func (c *Client) GetImage(imageRef string) (remote.Descriptor, error)
func (c *Client) GetImageHandle(imageRef string) (v1.Image, error)
func (c *Client) GetDigest(imageRef string) (string, error)
func (c *Client) GetPlatformDigests(imageRef string) (map[string]string, error)
func (c *Client) CheckExists(imageRef string) (bool, error)

// Copy operations
func (c *Client) CopyImage(srcRef, dstRef string, dstClient *Client) error
func (c *Client) CopyIndex(srcRef, dstRef string, dstClient *Client) error

// Fetch operations
func (c *Client) FetchPlatformImage(srcRef, platformDigest string) (v1.Image, error)

// Manifest list operations
func (c *Client) PushManifestList(manifestRef string, platformImages map[string]v1.Image) (string, error)

// Exported error types
var (
    ErrParseImageReference error
    ErrParseSourceReference error
    ErrParseDestinationReference error
    ErrParseManifestReference error
    ErrGetImage error
    ErrGetImageIndex error
)
```

## Design

- **OCI standard compliance**: Built on top of `google/go-containerregistry` library
- **Authentication support**: HTTP Basic Auth for private registries
- **Transport error handling**: Distinguishes between 404 (not found) vs other errors (network, auth)
- **Deterministic manifest lists**: Sorts platforms alphabetically for reproducible digests
- **Wrapped errors**: All errors use typed sentinel errors for programmatic error checking

## Dependencies

- External: `google/go-containerregistry` for OCI registry protocol implementation
- Internal: None (standalone module)

## Security Notes

- Credentials passed via HTTP Basic Auth
- Supports both tag-based and digest-based image references
- `CheckExists` properly distinguishes 404 errors from auth/network failures
