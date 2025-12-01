package sdk

import (
	"fmt"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/farcloser/quark/internal/reference"
)

// ImageOpts contains configuration options for creating an image reference.
type ImageOpts struct {
	Name    string `json:"name"`              // Required - image name (e.g., "alpine", "org/image", "ghcr.io/foo/bar")
	Domain  string `json:"domain,omitempty"`  // Optional - registry domain (default: docker.io)
	Version string `json:"version,omitempty"` // Optional - image tag/version
	Digest  string `json:"digest,omitempty"`  // Optional - image digest for verification

	// InsecureNoSignature bypasses signature verification (dangerous).
	// Use only for legacy unsigned images that cannot be signed.
	InsecureNoSignature bool `json:"insecureNoSignature,omitempty"`

	// SignedBy specifies trusted signers for this specific image.
	// If set, signature must match one of these identities (global signers ignored).
	// If empty, global plan signers are used.
	SignedBy []SignerIdentity `json:"signedBy,omitempty"`
}

// Image represents a container image reference with optional version and digest.
type Image struct {
	ref *reference.ImageReference
	log zerolog.Logger

	// Signature verification settings
	insecureNoSignature bool
	signedBy            []SignerIdentity
}

// NewImage creates a new Image from the provided arguments.
func NewImage(args *ImageOpts) (*Image, error) {
	name := strings.TrimSpace(args.Name)
	if name == "" {
		return nil, ErrImageNameRequired
	}

	// Construct reference string from args
	refString := ""
	if args.Domain != "" {
		refString = args.Domain + "/"
	}

	refString += name

	if args.Version != "" {
		refString += ":" + args.Version
	}

	if args.Digest != "" {
		refString += "@" + args.Digest
	}

	// Parse using reference package
	ref, err := reference.Parse(refString)
	if err != nil {
		if args.Digest != "" {
			return nil, fmt.Errorf("%w: %w", ErrInvalidImageDigest, err)
		}

		return nil, fmt.Errorf("invalid image reference: %w", err)
	}

	return &Image{
		ref:                 ref,
		log:                 log.Logger.With().Str("image", name).Logger(),
		insecureNoSignature: args.InsecureNoSignature,
		signedBy:            args.SignedBy,
	}, nil
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

// SetVersion sets the image version/tag.
func (img *Image) SetVersion(version string) {
	img.ref.Tag = version
	img.ref.ExplicitTag = version
}

// SetDigest sets the image digest.
func (img *Image) SetDigest(digestStr string) error {
	parsed, err := digest.Parse(digestStr)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidImageDigest, err)
	}

	img.ref.Digest = parsed

	return nil
}

// String returns the full serialized image reference.
// Format depends on what components are set:
//   - With digest: "domain/path:version@digest" or "domain/path@digest"
//   - Without digest: "domain/path:version" or "domain/path"
//
// Examples:
//   - "ghcr.io/farcloser/dns:v2025@sha256:379991..."
//   - "docker.io/library/alpine:3.19"
//   - "ghcr.io/org/image"
func (img *Image) String() string {
	result := img.ref.Name()

	// Add tag if present
	if img.ref.Tag != "" {
		result += ":" + img.ref.Tag
	}

	// Add digest if present
	if img.ref.Digest != "" {
		result += "@" + img.ref.Digest.String()
	}

	return result
}

// tagRef returns the tag reference format: "domain/name:version".
// Returns error if no tag is set.
func (img *Image) tagRef() string {
	return img.ref.Name() + ":" + img.ref.Tag
}

// digestRef returns the digest reference format: "domain/name@digest".
// Returns error if digest is not set.
func (img *Image) digestRef() (string, error) {
	if img.ref.Digest == "" {
		return "", fmt.Errorf("%w for image %q", ErrImageDigestRequired, img.ref.Path)
	}

	return img.ref.Name() + "@" + img.ref.Digest.String(), nil
}
