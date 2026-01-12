package registry2

import "github.com/google/go-containerregistry/pkg/v1/types"

type (
	// MediaType identifies the format of content (e.g., "application/vnd.oci.image.manifest.v1+json").
	MediaType = types.MediaType
	// LayerMediaType hints at the format of the blob linked by the descriptor.
	LayerMediaType string
	// ArtifactType describes the artifact type inside the blob layer (eg: SBOM).
	ArtifactType string
)

// #############################################################################
// OCI MEDIA TYPES
// These are used in OCI descriptors (manifest mediaType, layer mediaType, etc.)
// #############################################################################

// =============================================================================
// OCI Image Spec - Core Types
// =============================================================================

// OCI manifest and index media types.
const (
	MediaTypeOCIManifest = types.OCIManifestSchema1
	MediaTypeOCIIndex    = types.OCIImageIndex
)

// OCI config media type.
const (
	MediaTypeOCIConfig = types.OCIConfigJSON
)

// OCI layer media types.
const (
	MediaTypeOCILayer             = types.OCILayer
	MediaTypeOCILayerZstd         = types.OCILayerZStd
	MediaTypeOCILayerUncompressed = types.OCIUncompressedLayer
)

// OCI 1.1 artifact media types.
const (
	MediaTypeOCIEmptyJSON MediaType = "application/vnd.oci.empty.v1+json"
	MediaTypeOCILayout    MediaType = "application/vnd.oci.layout.header.v1+json"
)

// =============================================================================
// Docker - Core Types
// =============================================================================

// Docker manifest and index media types.
const (
	MediaTypeDockerManifest = types.DockerManifestSchema2
	MediaTypeDockerIndex    = types.DockerManifestList
)

// Docker config media type.
const (
	MediaTypeDockerConfig = types.DockerConfigJSON
)

// Docker layer media types.
const (
	MediaTypeDockerLayer             = types.DockerLayer
	MediaTypeDockerLayerUncompressed = types.DockerUncompressedLayer
)
