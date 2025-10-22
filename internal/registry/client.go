// Package registry provides OCI registry client operations.
package registry

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/rs/zerolog"
)

var (
	// ErrParseImageReference indicates failure parsing an image reference.
	ErrParseImageReference = errors.New("failed to parse image reference")
	// ErrParseSourceReference indicates failure parsing a source reference.
	ErrParseSourceReference = errors.New("failed to parse source reference")
	// ErrParseDestinationReference indicates failure parsing a destination reference.
	ErrParseDestinationReference = errors.New("failed to parse destination reference")
	// ErrParseManifestReference indicates failure parsing a manifest reference.
	ErrParseManifestReference = errors.New("failed to parse manifest reference")
	// ErrGetImage indicates failure retrieving an image from the registry.
	ErrGetImage = errors.New("failed to get image")
	// ErrGetImageIndex indicates failure retrieving an image index from the registry.
	ErrGetImageIndex = errors.New("failed to get image index")
)

// Client wraps OCI registry operations.
type Client struct {
	host     string
	username string
	password string
	log      zerolog.Logger
}

// NewClient creates a new registry client.
func NewClient(host, username, password string, log zerolog.Logger) *Client {
	return &Client{
		host:     host,
		username: username,
		password: password,
		log:      log,
	}
}

// GetImage retrieves an image descriptor from the registry.
func (client *Client) GetImage(imageRef string) (remote.Descriptor, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return remote.Descriptor{}, fmt.Errorf("%w: %w", ErrParseImageReference, err)
	}

	desc, err := remote.Get(ref, client.remoteOptions()...)
	if err != nil {
		return remote.Descriptor{}, fmt.Errorf("%w: %w", ErrGetImage, err)
	}

	return *desc, nil
}

// CopyImage copies an image from source to destination.
// Returns the source image object (fetched by digest) for trusted digest computation.
func (client *Client) CopyImage(srcRef, dstRef string, dstClient *Client) (v1.Image, error) {
	srcNameRef, err := name.ParseReference(srcRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseSourceReference, err)
	}

	dstNameRef, err := name.ParseReference(dstRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseDestinationReference, err)
	}

	client.log.Debug().
		Str("source", srcRef).
		Str("destination", dstRef).
		Msg("copying image")

	// Get source image (TRUSTED - must be called with digest reference)
	img, err := remote.Image(srcNameRef, client.remoteOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to get source image: %w", err)
	}

	// Push to destination
	if err := remote.Write(dstNameRef, img, dstClient.remoteOptions()...); err != nil {
		return nil, fmt.Errorf("failed to write destination image: %w", err)
	}

	// Return the TRUSTED source image (not fetched from destination)
	// This ensures digest is computed from content we verified by digest
	return img, nil
}

// CopyIndex copies a multi-platform image index from source to destination.
func (client *Client) CopyIndex(srcRef, dstRef string, dstClient *Client) error {
	srcNameRef, err := name.ParseReference(srcRef)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrParseSourceReference, err)
	}

	dstNameRef, err := name.ParseReference(dstRef)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrParseDestinationReference, err)
	}

	client.log.Debug().
		Str("source", srcRef).
		Str("destination", dstRef).
		Msg("copying image index")

	// Get source index
	idx, err := remote.Index(srcNameRef, client.remoteOptions()...)
	if err != nil {
		return fmt.Errorf("failed to get source index: %w", err)
	}

	// Push to destination
	if err := remote.WriteIndex(dstNameRef, idx, dstClient.remoteOptions()...); err != nil {
		return fmt.Errorf("failed to write destination index: %w", err)
	}

	return nil
}

// GetPlatformDigests returns platform-specific digests for a multi-platform image.
func (client *Client) GetPlatformDigests(imageRef string) (map[string]string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseImageReference, err)
	}

	// Get the image index
	idx, err := remote.Index(ref, client.remoteOptions()...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetImageIndex, err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get index manifest: %w", err)
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

// FetchPlatformImage fetches a specific platform image by digest from source.
// Returns the source image object (fetched by digest) for trusted manifest list creation.
// The image is NOT pushed - it will be pushed by digest when PushManifestList is called.
func (client *Client) FetchPlatformImage(srcRef, platformDigest string) (v1.Image, error) {
	// Parse source with digest
	srcDigestRef := fmt.Sprintf("%s@%s", srcRef, platformDigest)

	srcNameRef, err := name.ParseReference(srcDigestRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseSourceReference, err)
	}

	client.log.Debug().
		Str("source", srcDigestRef).
		Msg("fetching platform image")

	// Get source image by digest (TRUSTED - fetched by known digest)
	img, err := remote.Image(srcNameRef, client.remoteOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to get source image: %w", err)
	}

	// Return the TRUSTED source image (not fetched from destination)
	// This ensures manifest list is built from content we verified by digest
	// Note: remote.WriteIndex will push this image by digest (not by tag) when creating the manifest list
	return img, nil
}

// GetDigest returns the digest for an image reference.
func (client *Client) GetDigest(imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrParseImageReference, err)
	}

	desc, err := remote.Get(ref, client.remoteOptions()...)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrGetImage, err)
	}

	return desc.Digest.String(), nil
}

// PushManifestList creates and pushes a manifest list from platform-specific images.
// platformImages is a map of platform string (e.g., "linux/amd64") to image reference.
// Returns the digest of the created manifest list.
func (client *Client) PushManifestList(manifestRef string, platformImages map[string]v1.Image) (string, error) {
	client.log.Debug().
		Str("manifest", manifestRef).
		Int("platforms", len(platformImages)).
		Msg("creating and pushing manifest list")

	ref, err := name.ParseReference(manifestRef)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrParseManifestReference, err)
	}

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
		client.log.Debug().Str("platform", platform).Msg("adding platform to manifest list")

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
	if err := remote.WriteIndex(ref, idx, client.remoteOptions()...); err != nil {
		return "", fmt.Errorf("failed to push manifest list: %w", err)
	}

	// Get the digest of the pushed manifest list
	digest, err := idx.Digest()
	if err != nil {
		return "", fmt.Errorf("failed to get manifest list digest: %w", err)
	}

	client.log.Debug().Str("digest", digest.String()).Msg("manifest list pushed successfully")

	return digest.String(), nil
}

// CheckExists checks if an image exists in the registry.
// Returns (false, nil) only for 404/not found errors.
// Returns (false, err) for all other errors (network, auth, etc.).
func (client *Client) CheckExists(imageRef string) (bool, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrParseImageReference, err)
	}

	_, err = remote.Get(ref, client.remoteOptions()...)
	if err != nil {
		// Check if this is a 404/not found error
		var transportErr *transport.Error
		if errors.As(err, &transportErr) && transportErr.StatusCode == http.StatusNotFound {
			// Image doesn't exist - this is expected
			return false, nil
		}
		// Other errors (network, auth, etc.) should be returned
		return false, fmt.Errorf("failed to check image existence: %w", err)
	}

	return true, nil
}

// GetImageHandle fetches a v1.Image for the given reference.
// This is needed for creating manifest lists.
func (client *Client) GetImageHandle(imageRef string) (v1.Image, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseImageReference, err)
	}

	img, err := remote.Image(ref, client.remoteOptions()...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetImage, err)
	}

	return img, nil
}

// ListTags returns all tags for a repository.
func (client *Client) ListTags(repository string) ([]string, error) {
	repo, err := name.NewRepository(repository)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository: %w", err)
	}

	tags, err := remote.List(repo, client.remoteOptions()...)
	if err != nil {
		return nil, fmt.Errorf("failed to list tags: %w", err)
	}

	return tags, nil
}

// remoteOptions returns remote options with authentication.
func (client *Client) remoteOptions() []remote.Option {
	opts := []remote.Option{}

	if client.username != "" && client.password != "" {
		auth := &authn.Basic{
			Username: client.username,
			Password: client.password,
		}
		opts = append(opts, remote.WithAuth(auth))
	}

	return opts
}
