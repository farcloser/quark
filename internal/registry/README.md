# Package registry

## Purpose

Provides OCI-compliant container registry client operations for pulling, pushing, and synchronizing container images.

## Functionality

- **Authentication** - Ping registry to verify credentials
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
func NewClient(host, username, password string, log *slog.Logger) *Client

// Authentication
func (c *Client) Ping(ctx context.Context) error

// Retrieval operations
func (c *Client) GetImage(ctx context.Context, imageRef name.Reference) (remote.Descriptor, error)
func (c *Client) GetImageHandle(ctx context.Context, imageRef name.Reference) (v1.Image, error)
func (c *Client) GetDigest(ctx context.Context, imageRef name.Reference) (string, error)
func (c *Client) GetPlatformDigests(ctx context.Context, imageRef name.Reference) (map[string]string, error)
func (c *Client) CheckExists(ctx context.Context, imageRef name.Reference) (bool, error)
func (c *Client) ListTags(ctx context.Context, repository string) ([]string, error)

// Copy operations
func (c *Client) CopyImage(ctx context.Context, srcRef, dstRef name.Reference, dstClient *Client) (v1.Image, error)
func (c *Client) CopyIndex(ctx context.Context, srcRef, dstRef name.Reference, dstClient *Client) error

// Fetch operations
func (c *Client) FetchPlatformImage(ctx context.Context, srcRepo name.Repository, platformDigest string) (v1.Image, error)

// Manifest list operations
func (c *Client) PushManifestList(ctx context.Context, manifestRef name.Reference, platformImages map[string]v1.Image) (string, error)

// Errors
var (
    ErrAuthFailed             error
    ErrParseSourceReference   error
    ErrParseManifestReference error
    ErrGetImage               error
    ErrGetImageIndex          error
)
```

## Design

- **OCI standard compliance**: Built on `google/go-containerregistry` library
- **Context propagation**: All operations accept context for cancellation/timeout
- **Authentication support**: HTTP Basic Auth for private registries
- **Transport error handling**: Distinguishes 404 (not found) vs other errors (network, auth)
- **Deterministic manifest lists**: Sorts platforms alphabetically for reproducible digests
- **Wrapped errors**: Typed sentinel errors for programmatic error checking
- **Retry logic**: Automatic retry on rate limits and server errors with exponential backoff

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

- **Credential handling**: Credentials passed via HTTP Basic Auth
- **Digest support**: Supports both tag-based and digest-based image references
- **404 vs auth errors**: `CheckExists` properly distinguishes 404 from authentication failures
- **Trusted source images**: Copy operations return source image for digest computation (not fetched from destination)
