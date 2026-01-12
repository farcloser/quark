package image

import (
	"github.com/farcloser/quark/internal/registry2"
	"github.com/farcloser/quark/internal/types"
)

// =============================================================================
// Base Types (embedded by other structs, not exported)
// =============================================================================

// addressable contains fields common to all content-addressable objects.
type addressable struct {
	// content is the raw bytes of a JSON payload
	content *registry2.Content
	// If the resource is linked by a parent, this was its descriptor
	descriptor *registry2.Descriptor
	// If the resource has links, store them here
	linked []*addressable
	// If we have a subject, this is its descriptor
	subject *registry2.Descriptor
	// Source indicates how we retrieved the object.
	// This is fundamental to decide of the security of the object.
	// eg:
	// - direct resources are retrieved by digest
	// - embedded resources are secured by their parent
	// - tagged or referers
	source ArtifactSource
	// Referrers index, if any
	referersIndex *Index
	// Legacy index, if any
	legacyIndex *Index

	// referring to other objects - typically in the case of the ReferersIndex
	spuriousSignatures   []*Signature
	spuriousSBOM         []*SBOM
	spuriousAttestations []*Attestation

	// Presumably should not be exposed.
	Digest    types.Digest
	MediaType registry2.MediaType `json:"mediaType,omitempty"`

	// InlineAnnotations attached to this resource
	InlineAnnotations     map[string]string `json:"inlineannotations,omitempty"`
	DescriptorAnnotations map[string]string `json:"descriptorAnnotations,omitempty"`

	// Signatures attached to this resource.
	Signatures []*Signature
	// SBOM attached to this resource.
	SBOM []*SBOM
	// Attestations attached to this resource.
	Attestations []*Attestation
}

// artifact contains fields common to all referrer artifacts (signature, attestation, SBOM).
type artifact struct {
	addressable
}

// =============================================================================
// Complete Image Graph
// =============================================================================

// Graph represents a complete image with all its associated artifacts.
// This is the top-level structure returned when fully resolving an image reference.
// The root is always an Index (multi-platform images are the norm).
type Graph struct {
	// Reference is the original image reference (e.g., "registry.io/repo:tag").
	Reference *types.Image

	// Index is the top-level image index (manifest list).
	Index *Index
}

// =============================================================================
// Index
// =============================================================================

// Index represents an OCI image index (manifest list).
// Indexes can have signatures but not attestations or SBOMs (those are per-manifest).
type Index struct {
	addressable

	// parsed is the parsed registry Index.
	// purely for debugging
	parsed *registry2.Index

	// Manifests are the per-platform image manifests.
	Manifests []*Manifest

	// Nested indexes
	Indexes []*Index
}

// =============================================================================
// Manifest
// =============================================================================

// Manifest represents a single-platform OCI image manifest.
// Manifests can have signatures, attestations, and SBOMs attached.
type Manifest struct {
	addressable

	// parsed is the parsed registry Manifest.
	// purely for debugging
	parsed *registry2.Manifest

	// Config is the image configuration blob.
	Config *Config

	// Layers are the filesystem layer blobs.
	Layers []*Layer

	// Platform is this manifest target.
	Platform *types.Platform
}

// =============================================================================
// Config
// =============================================================================

// Config represents the image configuration blob.
type Config struct {
	// Digest of the config blob.
	Digest types.Digest

	// Size of the config in bytes.
	Size int64

	// MediaType distinguishes OCI vs Docker config format.
	MediaType registry2.MediaType

	// Raw JSON content.
	Raw []byte
}

// =============================================================================
// Layer
// =============================================================================

// Layer represents a filesystem layer blob.
type Layer struct {
	// Digest of the layer blob.
	Digest types.Digest

	// Size of the layer in bytes.
	Size int64

	// MediaType indicates the compression format (gzip, zstd, uncompressed).
	MediaType registry2.MediaType

	// Annotations from the layer descriptor.
	Annotations map[string]string
}

// =============================================================================
// Attestation
// =============================================================================

// Attestation represents an in-toto attestation wrapped in DSSE envelope.
// Attestations are attached to manifests, not indexes.
type Attestation struct {
	artifact

	// parsed is the parsed registry Manifest.
	// purely for debugging
	parsed *registry2.Manifest

	// Envelope is the DSSE envelope layer content.
	Envelope []byte

	// PredicateType identifies the attestation type (e.g., SLSA provenance).
	// Extracted from the in-toto statement inside the DSSE envelope.
	PredicateType string
}

// =============================================================================
// Artifact Source
// =============================================================================

// ArtifactSource indicates how an artifact (signature, attestation, SBOM) was discovered.
type ArtifactSource int

const (
	// SourceDirect means the artifact has been retrieved directly.
	SourceDirect ArtifactSource = iota

	// SourceReferrersAPI means the artifact was found via OCI 1.1 referrers API.
	SourceReferrersAPI

	// SourceFallbackIndex means the artifact was found in the sha256-XXX fallback index.
	SourceFallbackIndex

	// SourceLegacyTag means the artifact was found via cosign legacy tag (.sig, .att).
	SourceLegacyTag
)
