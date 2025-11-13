package sdk

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/internal/reference"
)

// Image represents a container image reference with optional version and digest.
type Image struct {
	ref *reference.ImageReference
	log zerolog.Logger

	// Builder state (fields set before Build() is called)
	builderName    string
	builderDomain  string
	builderVersion string
	builderDigest  string
}

// ImageBuilder builds an Image.
type ImageBuilder struct {
	image *Image
	built bool
}

// NewImage creates a new Image builder with the specified name.
// Name can be a short name, repository path, or fully qualified reference:
//   - Short: "alpine", "debian" (normalized to docker.io/library/alpine, docker.io/library/debian)
//   - Repository: "timberio/vector", "org/image" (normalized to docker.io/timberio/vector, docker.io/org/image)
//   - Fully qualified: "ghcr.io/foo/bar:v1.0", "docker.io/library/alpine:3.19"
//
// You can also use Domain(), Version(), and Digest() methods to set components explicitly.
func NewImage(name string) *ImageBuilder {
	return &ImageBuilder{
		image: &Image{
			builderName: name,
			log:         log.Logger.With().Str("image", name).Logger(),
		},
	}
}

// Domain sets the registry domain for the image.
// Empty string will be normalized to "docker.io" (Docker Hub).
func (builder *ImageBuilder) Domain(domain string) *ImageBuilder {
	builder.image.builderDomain = domain

	return builder
}

// Version sets the image version/tag.
// Can include variant suffix (e.g., "0.50.0-distroless-static").
func (builder *ImageBuilder) Version(version string) *ImageBuilder {
	builder.image.builderVersion = version

	return builder
}

// Digest sets the image digest for verification and secure operations.
func (builder *ImageBuilder) Digest(digest string) *ImageBuilder {
	builder.image.builderDigest = digest

	return builder
}

// Build validates and returns the Image.
// The builder becomes unusable after Build() is called.
// Create a new builder for each operation.
func (builder *ImageBuilder) Build() (*Image, error) {
	if builder.built {
		return nil, ErrBuilderAlreadyUsed
	}

	builder.built = true

	name := strings.TrimSpace(builder.image.builderName)
	if name == "" {
		return nil, ErrImageNameRequired
	}

	// Construct reference string from builder fields
	refString := ""
	if builder.image.builderDomain != "" {
		refString = builder.image.builderDomain + "/"
	}

	refString += name

	if builder.image.builderVersion != "" {
		refString += ":" + builder.image.builderVersion
	}

	if builder.image.builderDigest != "" {
		refString += "@" + builder.image.builderDigest
	}

	// Parse using reference package
	ref, err := reference.Parse(refString)
	if err != nil {
		// If we have a digest and parsing failed, it's likely a digest error
		if builder.image.builderDigest != "" {
			return nil, fmt.Errorf("%w: %w", ErrInvalidImageDigest, err)
		}

		return nil, fmt.Errorf("invalid image reference: %w", err)
	}

	builder.image.ref = ref

	return builder.image, nil
}

// Name returns the image name in familiar form (user-facing).
// Returns shortened form for Docker Hub official images: "alpine" instead of "library/alpine".
// For the canonical repository path, use Path().
func (img *Image) Name() string {
	return img.ref.FamiliarName()
}

// Path returns the canonical repository path (e.g., "library/alpine", "timberio/vector").
// This is the full path as stored in the registry, which may differ from Name() for official images.
func (img *Image) Path() string {
	return img.ref.Path
}

// Domain returns the image registry domain (normalized).
// Empty domain is normalized to "docker.io".
func (img *Image) Domain() string {
	return img.ref.Domain
}

// Version returns the image version/tag if explicitly set.
// Returns empty string if no version was provided.
func (img *Image) Version() string {
	return img.ref.ExplicitTag
}

// Digest returns the image digest if set.
func (img *Image) Digest() string {
	if img.ref.Digest == "" {
		return ""
	}

	return img.ref.Digest.String()
}

// tagRef returns the tag reference format: "domain/name:version".
// Returns error if version is not set.
func (img *Image) tagRef() (string, error) {
	if img.ref.ExplicitTag == "" {
		return "", fmt.Errorf("%w for image %q", ErrImageVersionRequired, img.ref.Path)
	}

	return img.ref.Name() + ":" + img.ref.Tag, nil
}

// digestRef returns the digest reference format: "domain/name@digest".
// Returns error if digest is not set.
func (img *Image) digestRef() (string, error) {
	if img.ref.Digest == "" {
		return "", fmt.Errorf("%w for image %q", ErrImageDigestRequired, img.ref.Path)
	}

	return img.ref.Name() + "@" + img.ref.Digest.String(), nil
}
