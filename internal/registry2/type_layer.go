package registry2

// =============================================================================
// Signatures & Attestations - OCI Layer Types
// =============================================================================

// DSSE envelope layer media type (wraps attestations).
const (
	LayerMediaTypeDSSEEnvelope MediaType = "application/vnd.dsse.envelope.v1+json"
)

// In-toto payload type (used inside DSSE envelope's payloadType field as well).
const (
	LayerMediaTypeInToto MediaType = "application/vnd.in-toto+json"
)

// =============================================================================
// SBOMs - OCI Layer Types
// =============================================================================

// CycloneDX SBOM layer media type.
const (
	LayerMediaTypeCycloneDXJSON MediaType = "application/vnd.cyclonedx+json"
)

// #############################################################################
// Tier 2 layer types that we may want to support in the future.
// #############################################################################

const (
	// Tier2LayerMediaTypeSPDXJSON SPDX SBOM media types - we use CycloneDX instead.
	Tier2LayerMediaTypeSPDXJSON MediaType = "application/spdx+json"
	// Tier2LayerMediaTypeSPDXText SPDX SBOM media types - we use CycloneDX instead.
	Tier2LayerMediaTypeSPDXText MediaType = "text/spdx"
)

const (
	// Tier2LayerMediaTypeCycloneDXXML CycloneDX XML - we use JSON instead.
	Tier2LayerMediaTypeCycloneDXXML MediaType = "application/vnd.cyclonedx+xml"
)

const (
	// Tier2LayerMediaTypeSyftJSON Syft native format - we export to CycloneDX instead.
	Tier2LayerMediaTypeSyftJSON MediaType = "application/vnd.syft+json"
)

const (
	// Tier3LayerMediaTypeInTotoBundle ?
	Tier3LayerMediaTypeInTotoBundle MediaType = "application/vnd.in-toto.bundle+json"
)
