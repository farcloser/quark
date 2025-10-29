package sdk

import (
	"fmt"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Image represents a container image reference with optional version and digest.
type Image struct {
	name    string
	domain  string // Registry domain (e.g., "docker.io", "ghcr.io")
	version string
	digest  string
	log     zerolog.Logger
}

// ImageBuilder builds an Image.
type ImageBuilder struct {
	image *Image
}

// NewImage creates a new Image builder with the specified name.
// Name should be the repository name without the registry domain (e.g., "timberio/vector", "org/image").
// Use Domain() to specify the registry domain.
func NewImage(name string) *ImageBuilder {
	return &ImageBuilder{
		image: &Image{
			name: name,
			log:  log.Logger.With().Str("image", name).Logger(),
		},
	}
}

// Domain sets the registry domain for the image.
// Empty string will be normalized to "docker.io" (Docker Hub).
func (builder *ImageBuilder) Domain(domain string) *ImageBuilder {
	builder.image.domain = domain

	return builder
}

// Version sets the image version/tag.
// Can include variant suffix (e.g., "0.50.0-distroless-static").
func (builder *ImageBuilder) Version(version string) *ImageBuilder {
	builder.image.version = version

	return builder
}

// Digest sets the image digest for verification and secure operations.
func (builder *ImageBuilder) Digest(digest string) *ImageBuilder {
	builder.image.digest = digest

	return builder
}

// Build validates and returns the Image.
func (builder *ImageBuilder) Build() (*Image, error) {
	if builder.image.name == "" {
		return nil, ErrImageNameRequired
	}

	return builder.image, nil
}

// Name returns the image name.
func (img *Image) Name() string {
	return img.name
}

// Domain returns the image registry domain.
func (img *Image) Domain() string {
	return img.domain
}

// Version returns the image version/tag.
func (img *Image) Version() string {
	return img.version
}

// Digest returns the image digest.
func (img *Image) Digest() string {
	return img.digest
}

// Returns: "domain/name:version".
func (img *Image) tagRef() (string, error) {
	if img.version == "" {
		return "", fmt.Errorf("%w for image %q", ErrImageVersionRequired, img.name)
	}

	// Normalize domain (empty → docker.io)
	domain := normalizeDomain(img.domain)

	return fmt.Sprintf("%s/%s:%s", domain, img.name, img.version), nil
}

// Returns: "domain/name@digest".
func (img *Image) digestRef() (string, error) {
	if img.digest == "" {
		return "", fmt.Errorf("%w for image %q", ErrImageDigestRequired, img.name)
	}

	// Normalize domain (empty → docker.io)
	domain := normalizeDomain(img.domain)

	return fmt.Sprintf("%s/%s@%s", domain, img.name, img.digest), nil
}
