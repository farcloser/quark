package registry2

import (
	"context"
	"io"
	"strings"

	quarktypes "github.com/farcloser/quark/internal/types"
)

// SignatureImage returns a new Image pointing to the cosign-compatible signature tag
// for the given image. The input image must have a Digest set.
// Format: sha256-XXXXX.sig.
func SignatureImage(img *quarktypes.Image) *quarktypes.Image {
	return &quarktypes.Image{
		Registry: img.Registry,
		Path:     img.Path,
		// sha256:abc123 -> sha256-abc123.sig
		Tag: strings.ReplaceAll(img.Digest.String(), ":", "-") + ".sig",
	}
}

// AttestationImage returns a new Image pointing to the cosign-compatible attestation tag
// for the given image. The input image must have a Digest set.
// Format: sha256-XXXXX.att.
func AttestationImage(img *quarktypes.Image) *quarktypes.Image {
	return &quarktypes.Image{
		Registry: img.Registry,
		Path:     img.Path,
		// sha256:abc123 -> sha256-abc123.att
		Tag: strings.ReplaceAll(img.Digest.String(), ":", "-") + ".att",
	}
}

// SBOMImage returns a new Image pointing to the cosign-compatible sbom tag
// for the given image. The input image must have a Digest set.
// Format: sha256-XXXXX.sbom.
func SBOMImage(img *quarktypes.Image) *quarktypes.Image {
	return &quarktypes.Image{
		Registry: img.Registry,
		Path:     img.Path,
		// sha256:abc123 -> sha256-abc123.sbom
		Tag: strings.ReplaceAll(img.Digest.String(), ":", "-") + ".sbom",
	}
}

// FallbackIndex returns a fallback index for non-referer able registries.
// Format: sha256-XXXXX.
func FallbackIndex(img *quarktypes.Image) *quarktypes.Image {
	return &quarktypes.Image{
		Registry: img.Registry,
		Path:     img.Path,
		// sha256:abc123 -> sha256-abc123
		Tag: strings.ReplaceAll(img.Digest.String(), ":", "-"),
	}
}

// Client handles all OCI registry operations.
// Credentials are provided per-operation via types.Image.Registry.
type Client interface {
	// === Authentication & Discovery ===

	// Ping verifies credentials are valid by hitting /v2/ endpoint.
	Ping(ctx context.Context, img *quarktypes.Image) error

	// === Resolution ===

	// ResolveDigest resolves a tag to its canonical digest.
	// If img already has a digest, validates existence and returns it.
	// Returns ErrNotFound if the image does not exist.
	ResolveDigest(ctx context.Context, img *quarktypes.Image) (quarktypes.Digest, error)

	// ListTags returns all tags in the repository.
	ListTags(ctx context.Context, img *quarktypes.Image) ([]string, error)

	// === Reading Manifests & Indexes ===

	// ReadManifest fetches manifest or index content.
	// The image must have a Digest set.
	// Use Content.ParseIndex() or Content.ParseManifest() to get structured data.
	ReadManifest(ctx context.Context, img *quarktypes.Image) (*Content, error)

	// ListReferrers returns the index of manifests that reference the given image.
	// The image must have a Digest set.
	// Returns empty index if no referrers exist.
	ListReferrers(ctx context.Context, img *quarktypes.Image) (*Content, error)

	// === Reading Blobs (Layers & Configs) ===

	// ReadBlob fetches a blob by digest.
	// Caller must close the returned reader.
	ReadBlob(ctx context.Context, img *quarktypes.Image, digest quarktypes.Digest) (io.ReadCloser, error)

	// === Writing Manifests & Indexes ===

	// WriteManifest pushes manifest or index content and returns its digest.
	// If img has a tag, the tag will point to this content.
	// Content can be from ReadManifest (copy) or Manifest.ToContent()/Index.ToContent() (create).
	WriteManifest(ctx context.Context, img *quarktypes.Image, content *Content) (quarktypes.Digest, error)

	// === Writing Blobs ===

	// WriteBlob uploads a blob with a known digest.
	// The digest must match the content; the registry will reject mismatches.
	// Content is streamed directly without buffering.
	WriteBlob(ctx context.Context, img *quarktypes.Image, digest quarktypes.Digest, size int64, content io.Reader) error

	// === Deletion ===

	// DeleteManifest removes a manifest reference (tag or digest) from the repository.
	// The image must have either a tag or digest set.
	// Does not delete underlying blobs (garbage collection is registry-specific).
	DeleteManifest(ctx context.Context, img *quarktypes.Image) error

	// === Local Export ===
	//
	// ExportToOCITarball downloads an image/index to a local OCI tarball.
	// For multi-platform images, platforms filters which platforms to include (nil = all).
	// The tarball can be used with syft for SBOM generation.
	//
	// ExportToOCITarball(
	//	ctx context.Context,
	//	img *quarktypes.Image,
	//	platforms []*quarktypes.Platform,
	//	destPath string,
	// ) error
	//
	// === Cross-Registry Copy ===
	//
	// CopyTo copies an image from src to dst.
	// Performs incremental copy: only transfers blobs missing at destination.
	// For multi-platform images, platforms filters which platforms to copy (nil = all).
	// Returns the digest of the copied content.
	//
	// CopyTo(
	//	ctx context.Context,
	//	src *quarktypes.Image,
	//	dst *quarktypes.Image,
	//	platforms []*quarktypes.Platform,
	// ) (quarktypes.Digest, error)
}

// NewClient creates a new registry client.
func NewClient() Client {
	return &client{}
}
