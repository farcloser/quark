# Package registry

## Purpose

Provides OCI-compliant container registry client operations for pulling, pushing, and synchronizing container images.

## Functionality

- **Image retrieval** - Fetch image descriptors and metadata from registries
- **Image copying** - Transfer images between registries (single-platform and multi-platform)
- **Manifest list management** - Create and push multi-platform manifest lists
- **Digest operations** - Extract and verify image digests
- **Existence checks** - Verify if images exist in registries (with proper 404 handling)
- **Tag listing** - Enumerate all tags for a repository
- **Retry and backoff** - Automatic retry for rate limits (429) and transient server errors (5xx)

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
func (c *Client) ListTags(repository string) ([]string, error)

// Copy operations
func (c *Client) CopyImage(srcRef, dstRef string, dstClient *Client) (v1.Image, error)
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
- **Retry logic**: Automatic retry on rate limits (429) and server errors (500-504) with exponential backoff (1s, 2s, 4s, 8s, 16s)

## Retry Behavior

Registry operations automatically retry on:
- HTTP 429 (Too Many Requests)
- HTTP 500 (Internal Server Error)
- HTTP 502 (Bad Gateway)
- HTTP 503 (Service Unavailable)
- HTTP 504 (Gateway Timeout)

Backoff strategy: 1s, 2s, 4s, 8s, 16s (up to 5 attempts total)

## Dependencies

- External: `google/go-containerregistry` for OCI registry protocol implementation
- Internal: None (standalone module)

## Security Considerations

- **Credential handling**: Credentials passed via HTTP Basic Auth (handled by go-containerregistry)
- **Digest support**: Supports both tag-based and digest-based image references
- **404 vs auth errors**: `CheckExists` properly distinguishes 404 (not found) from authentication failures
- **Transport security**: All registry operations use HTTPS by default
