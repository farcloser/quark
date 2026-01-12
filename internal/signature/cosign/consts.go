package cosign

import "github.com/farcloser/quark/internal/types"

const (
	annotationSignature   = "dev.cosignproject.cosign/signature"
	annotationCertificate = "dev.sigstore.cosign/certificate"
	annotationBundle      = "dev.sigstore.cosign/bundle"
	bundleVersion         = "0.3"

	// Attestation layer media type (DSSE envelope).
	layerMediaTypeDSSE types.MediaType = "application/vnd.dsse.envelope.v1+json"

	// In-toto statement type and signature predicate type used to generate sigstore bundles.
	statementTypeInToto    = "https://in-toto.io/Statement/v1"
	predicateTypeSignature = "https://sigstore.dev/cosign/sign/v1"
)
