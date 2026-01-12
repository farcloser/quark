package registry2

/*
Deprecated/legacy/unused media types kept for reference.

import "github.com/google/go-containerregistry/pkg/v1/types"

// #############################################################################
// DEPRECATED OCI MEDIA TYPES
// #############################################################################

// Non-distributable layer media types (OCI) - deprecated in OCI spec.
const (
	MediaTypeOCILayerNonDistributable             = types.OCIRestrictedLayer
	MediaTypeOCILayerNonDistributableUncompressed = types.OCIUncompressedRestrictedLayer
	MediaTypeOCILayerNonDistributableZstd         = "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd"
)

// #############################################################################
// DEPRECATED DOCKER MEDIA TYPES
// #############################################################################

// Docker schema v1 - deprecated, predates content-addressable storage.
const (
	MediaTypeDockerManifestV1       = types.DockerManifestSchema1
	MediaTypeDockerManifestV1Signed = types.DockerManifestSchema1Signed
)

// Docker plugin config - legacy extension mechanism.
const (
	MediaTypeDockerPluginConfig = types.DockerPluginConfig
)

// Docker foreign layers - for Windows base images with redistribution restrictions.
const (
	MediaTypeDockerForeignLayer = types.DockerForeignLayer
)

// #############################################################################
// UNUSED OCI LAYER TYPES
// #############################################################################

// Not a real-life media-type.
const (
	MediaTypeOCIDescriptor MediaType = types.OCIContentDescriptor
)

// Notary v2 signature media types - we use cosign/sigstore instead.
const (
	MediaTypeNotarySignatureJWS  MediaType = "application/jose+json"
	MediaTypeNotarySignatureCOSE MediaType = "application/cose"
)

// WASM legacy media types - superseded by CNCF standard.
const (
	MediaTypeWASMConfigV1  MediaType = "application/vnd.wasm.config.v1+json"
	MediaTypeWASMContentV1 MediaType = "application/vnd.wasm.content.layer.v1+wasm"
)

// Helm chart media types - not currently used.
const (
	MediaTypeHelmConfig     MediaType = "application/vnd.cncf.helm.config.v1+json"
	MediaTypeHelmContent    MediaType = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
	MediaTypeHelmProvenance MediaType = "application/vnd.cncf.helm.chart.provenance.v1.prov"
)

// =============================================================================
// WebAssembly - OCI Types
// =============================================================================

// WASM artifact media types (CNCF standard).
const (
	MediaTypeWASMConfig MediaType = "application/vnd.wasm.config.v0+json"
	MediaTypeWASM       MediaType = "application/wasm"
)

// WASM component media types (W3C proposal).
const (
	MediaTypeWASMComponentConfig MediaType = "application/vnd.w3c.wasm.component.v1+json"
	MediaTypeWASMComponent       MediaType = "application/vnd.w3c.wasm.component.v1+wasm"
	MediaTypeWASMModuleConfig    MediaType = "application/vnd.w3c.wasm.module.v1+json"
	MediaTypeWASMModule          MediaType = "application/vnd.w3c.wasm.module.v1+wasm"
)

*/
