package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"

	errors2 "github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/dev/network"
	"github.com/farcloser/quark/internal/reference"
	types2 "github.com/farcloser/quark/internal/types"
)

// Client wraps OCI registry operations.
type Client struct {
	creds *types2.RegistryCredentials
	log   *slog.Logger
}

// NewClient creates a new registry client.
func NewClient(creds *types2.RegistryCredentials, log *slog.Logger) *Client {
	if creds == nil {
		creds = &types2.RegistryCredentials{}
	}

	return &Client{
		creds: creds,
		log:   log,
	}
}

// Ping verifies authentication with the registry by hitting the /v2/ endpoint.
// This is a lightweight preflight check that negotiates credentials.
func (client *Client) Ping(ctx context.Context) error {
	reg, err := name.NewRegistry(client.creds.Domain)
	if err != nil {
		return fmt.Errorf("%w: invalid registry %q: %w", errors2.ErrInvalidArgument, client.creds.Domain, err)
	}

	// Build authenticated transport for the /v2/ endpoint
	auth := authn.Anonymous
	if client.creds.Username != "" && client.creds.Password != "" {
		auth = &authn.Basic{
			Username: client.creds.Username,
			Password: client.creds.Password,
		}
	}

	// Create transport with auth negotiation
	authTransport, err := transport.NewWithContext(
		ctx, reg, auth, http.DefaultTransport, []string{reg.Scope(transport.PullScope)},
	)
	if err != nil {
		return fmt.Errorf("%w: %w", errors2.ErrAuthenticationFailure, err)
	}

	// Hit the /v2/ endpoint directly
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/v2/", reg.Name()), nil)
	if err != nil {
		return fmt.Errorf("%w: %w", errors2.ErrAuthenticationFailure, err)
	}

	resp, err := authTransport.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("%w: %w", errors2.ErrAuthenticationFailure, err)
	}
	defer resp.Body.Close()

	// 200 or 401 with www-authenticate means registry is reachable
	// 401/403 after auth negotiation means bad credentials
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w: status %d", errors2.ErrAuthenticationFailure, resp.StatusCode)
	}

	return nil
}

// GetImage retrieves an image descriptor from the registry.
func (client *Client) GetImage(ctx context.Context, imageRef reference.ImageReference) (remote.Descriptor, error) {
	desc, err := remote.Get(toGCRRef(imageRef), client.remoteOptionsWithContext(ctx)...)
	if err != nil {
		return remote.Descriptor{}, fmt.Errorf("%w: %w", ErrGetImage, err)
	}

	return *desc, nil
}

// CopyImage copies an image from source to destination.
// Returns the digest of the copied image (computed from source, not destination).
func (client *Client) CopyImage(
	ctx context.Context,
	srcRef, dstRef reference.ImageReference,
	dstClient *Client,
) (string, error) {
	client.log.DebugContext(
		ctx,
		"copying image",
		"source",
		srcRef.String(),
		"destination",
		dstRef.String(),
	) //revive:disable-line:add-constant

	// Get source image (TRUSTED - must be called with digest reference)
	img, err := remote.Image(toGCRRef(srcRef), client.remoteOptionsWithContext(ctx)...)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrGetSourceImage, err)
	}

	// Push to destination
	if err := remote.Write(toGCRRef(dstRef), img, dstClient.remoteOptionsWithContext(ctx)...); err != nil {
		return "", fmt.Errorf("%w: %w", ErrWriteDestinationImage, err)
	}

	// Compute digest from TRUSTED source image (not from destination)
	digest, err := img.Digest()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrComputeDigest, err)
	}

	return digest.String(), nil
}

// CopyIndex copies a multi-platform image index from source to destination.
func (client *Client) CopyIndex(ctx context.Context, srcRef, dstRef reference.ImageReference, dstClient *Client) error {
	client.log.DebugContext(
		ctx,
		"copying image index",
		"source",
		srcRef.String(),
		"destination",
		dstRef.String(),
	) //revive:disable-line:add-constant

	// Get source index
	idx, err := remote.Index(toGCRRef(srcRef), client.remoteOptionsWithContext(ctx)...)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrGetSourceIndex, err)
	}

	// Push to destination
	if err := remote.WriteIndex(toGCRRef(dstRef), idx, dstClient.remoteOptionsWithContext(ctx)...); err != nil {
		return fmt.Errorf("%w: %w", ErrWriteDestinationIndex, err)
	}

	return nil
}

// GetPlatformDigests returns platform-specific digests for a multi-platform image.
func (client *Client) GetPlatformDigests(
	ctx context.Context,
	imageRef reference.ImageReference,
) (map[string]string, error) {
	// Get the image index
	idx, err := remote.Index(toGCRRef(imageRef), client.remoteOptionsWithContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetImageIndex, err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetIndexManifest, err)
	}

	// Extract platform digests
	platformDigests := make(map[string]string)

	for _, desc := range manifest.Manifests {
		if desc.Platform != nil {
			platform := fmt.Sprintf("%s/%s", desc.Platform.OS, desc.Platform.Architecture)
			platformDigests[platform] = desc.Digest.String()
		}
	}

	return platformDigests, nil
}

// SyncMultiPlatform syncs a multi-platform image from source to destination.
// It fetches each requested platform from source and creates a manifest list at destination.
// Returns the digest of the created manifest list (computed locally for security).
func (client *Client) SyncMultiPlatform(
	ctx context.Context,
	srcImage, dstImage reference.ImageReference,
	srcClient *Client,
	platforms []string,
) (string, error) {
	// Get platform-specific digests from source
	platformDigests, err := srcClient.GetPlatformDigests(ctx, srcImage)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrGetImageIndex, err)
	}

	client.log.DebugContext(
		ctx,
		"found platforms in source image",
		"platforms",
		len(platformDigests),
	) //revive:disable-line:add-constant

	// Fetch each requested platform and collect images
	platformImages := make(map[string]v1.Image)

	for platform, digest := range platformDigests {
		// Check context cancellation before each platform
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("%w: %w", errors2.ErrContext, err)
		}

		// Skip platforms not in the requested list
		if !containsString(platforms, platform) {
			client.log.DebugContext(
				ctx,
				"skipping platform not in requested list",
				"platform",
				platform,
			) //revive:disable-line:add-constant

			continue
		}

		client.log.DebugContext(
			ctx,
			"fetching platform image",
			"platform",
			platform,
			"digest",
			digest,
		) //revive:disable-line:add-constant

		img, err := srcClient.fetchPlatformImage(ctx, srcImage, digest)
		if err != nil {
			return "", fmt.Errorf("%w %s: %w", ErrFetchPlatformImage, platform, err)
		}

		platformImages[platform] = img
	}

	// Create and push manifest list to destination
	client.log.DebugContext(
		ctx,
		"creating manifest list",
		"destination", //revive:disable-line:add-constant
		dstImage.String(),
	)

	manifestDigest, err := client.pushManifestList(ctx, dstImage, platformImages)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrPushManifestList, err)
	}

	client.log.DebugContext(
		ctx,
		"manifest list created successfully",
		"digest",
		manifestDigest,
	) //revive:disable-line:add-constant

	return manifestDigest, nil
}

// containsString checks if a string slice contains a specific string.
func containsString(slice []string, s string) bool {
	return slices.Contains(slice, s)
}

// GetDigest returns the digest for an image reference.
func (client *Client) GetDigest(ctx context.Context, imageRef reference.ImageReference) (string, error) {
	desc, err := remote.Get(toGCRRef(imageRef), client.remoteOptionsWithContext(ctx)...)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrGetImage, err)
	}

	return desc.Digest.String(), nil
}

// CheckExists checks if an image exists in the registry.
// Returns (false, nil) only for 404/not found errors.
// Returns (false, err) for all other errors (network, auth, etc.).
func (client *Client) CheckExists(ctx context.Context, imageRef reference.ImageReference) (bool, error) {
	_, err := remote.Get(toGCRRef(imageRef), client.remoteOptionsWithContext(ctx)...)
	if err != nil {
		// Check if this is a 404/not found error
		var transportErr *transport.Error
		if errors.As(err, &transportErr) && transportErr.StatusCode == http.StatusNotFound {
			// Image doesn't exist - this is expected
			return false, nil
		}
		// Other errors (network, auth, etc.) should be returned
		return false, fmt.Errorf("%w: %w", ErrCheckImageExistence, err)
	}

	return true, nil
}

// GetImageHandle fetches a v1.Image for the given reference.
// This is needed for creating manifest lists.
func (client *Client) GetImageHandle(ctx context.Context, imageRef reference.ImageReference) (v1.Image, error) {
	img, err := remote.Image(toGCRRef(imageRef), client.remoteOptionsWithContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetImage, err)
	}

	return img, nil
}

// WriteImage pushes an image to the registry at the given reference.
func (client *Client) WriteImage(ctx context.Context, imageRef reference.ImageReference, img v1.Image) error {
	if err := remote.Write(toGCRRef(imageRef), img, client.remoteOptionsWithContext(ctx)...); err != nil {
		return fmt.Errorf("%w: %w", ErrWriteImage, err)
	}

	return nil
}

// ListTags returns all tags for an image reference's repository.
func (client *Client) ListTags(ctx context.Context, imageRef reference.ImageReference) ([]string, error) {
	repo := toGCRRef(imageRef).Context()

	tags, err := remote.List(repo, client.remoteOptionsWithContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrListTags, err)
	}

	return tags, nil
}

// fetchPlatformImage fetches a specific platform image by digest from source.
// Returns the source image object (fetched by digest) for trusted manifest list creation.
func (client *Client) fetchPlatformImage(
	ctx context.Context,
	imageRef reference.ImageReference,
	platformDigest string,
) (v1.Image, error) {
	// Build digest reference from the image repository
	srcDigestRef := fmt.Sprintf("%s@%s", toGCRRef(imageRef).Context(), platformDigest)

	srcNameRef, err := name.ParseReference(srcDigestRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseSourceReference, err)
	}

	client.log.DebugContext(ctx, "fetching platform image", "source", srcDigestRef) //revive:disable-line:add-constant

	// Get source image by digest (TRUSTED - fetched by known digest)
	img, err := remote.Image(srcNameRef, client.remoteOptionsWithContext(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetSourceImage, err)
	}

	return img, nil
}

// pushManifestList creates and pushes a manifest list from platform-specific images.
// platformImages is a map of platform string (e.g., "linux/amd64") to image.
// Returns the digest of the created manifest list.
func (client *Client) pushManifestList(
	ctx context.Context,
	manifestRef reference.ImageReference,
	platformImages map[string]v1.Image,
) (string, error) {
	client.log.DebugContext( //revive:disable-line:add-constant
		ctx,
		"creating and pushing manifest list",
		"manifest",
		manifestRef.String(),
		"platforms",
		len(platformImages),
	)

	// Start with an empty index
	idx := mutate.IndexMediaType(empty.Index, types.DockerManifestList)

	// Sort platforms for deterministic ordering
	// Go map iteration is randomized, which would produce different digests for identical content
	platforms := make([]string, 0, len(platformImages))
	for platform := range platformImages {
		platforms = append(platforms, platform)
	}

	sort.Strings(platforms)

	// Add each platform image to the index in sorted order
	for _, platform := range platforms {
		img := platformImages[platform]

		client.log.DebugContext(
			ctx,
			"adding platform to manifest list",
			"platform", //revive:disable-line:add-constant
			platform,
		)

		// Extract OS and architecture from platform string (e.g., "linux/amd64")
		parts := strings.SplitN(platform, "/", 2)
		osName, archName := parts[0], parts[1]

		// Add image to index with platform specification
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{
					OS:           osName,
					Architecture: archName,
				},
			},
		})
	}

	// Push the manifest list
	if err := remote.WriteIndex(toGCRRef(manifestRef), idx, client.remoteOptionsWithContext(ctx)...); err != nil {
		return "", fmt.Errorf("%w: %w", ErrPushManifestList, err)
	}

	// Get the digest of the pushed manifest list
	digest, err := idx.Digest()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrGetManifestListDigest, err)
	}

	client.log.DebugContext(
		ctx,
		"manifest list pushed successfully",
		"digest", //revive:disable-line:add-constant
		digest.String(),
	)

	return digest.String(), nil
}

// toGCRRef converts an ImageReference to a go-containerregistry Reference.
// This is a private helper to encapsulate the go-containerregistry dependency.
func toGCRRef(imageRef reference.ImageReference) name.Reference {
	// By the time we call this, we have already parsed and validated the image
	ref, err := name.ParseReference(imageRef.String())
	if err != nil {
		panic(err)
	}

	return ref
}

// remoteOptionsWithContext returns remote options with context, authentication, and retry configuration.
func (client *Client) remoteOptionsWithContext(ctx context.Context) []remote.Option {
	auth := authn.Anonymous
	if client.creds.Username != "" && client.creds.Password != "" {
		auth = &authn.Basic{
			Username: client.creds.Username,
			Password: client.creds.Password,
		}
	}

	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithTransport(http.DefaultTransport),
		remote.WithAuth(auth),
		// Retry on rate limits and transient server errors
		remote.WithRetryStatusCodes(network.RetryStatusCodes...),
		// Use exponential backoff: 1s, 2s, 4s, 8s, 16s (max 5 attempts)
		remote.WithRetryBackoff(remote.Backoff{
			Duration: 1 * time.Second,
			Factor:   2.0,
			Jitter:   0.1,
			Steps:    5,
		}),
	}
}
