package cosign

import "errors"

var (
	errFailedExtractingCertChain   = errors.New("failed extracting certificate chain")
	errFailedBuildingSignature     = errors.New("failed building signature")
	errFailedExtractingTLogEntries = errors.New("failed extracting tlog entries")
	errFailedParsingDSSEEnvelope   = errors.New("failed parsing DSSE envelope")

	//	errUnrecognizedMediaType = errors.New("unrecognized media type")
	//
	//	errRekorTimestampVerificationFailed = errors.New("rekor timestamp verification failed")
	//	errMissingSignature                 = errors.New("missing signature")
	//	errNoCertificateForKeyless          = errors.New(
	//		"no certificate found, use VerifyWithKey for key-based attestations",
	//	)
	//
	//	errDigestMismatch                       = errors.New("digest mismatch")
	//	errAttestationParseFailed               = errors.New("attestation parse failed")
	//	errAttestationKeyVerificationFailed     = errors.New("attestation key-based verification failed")
	//	errAttestationKeylessVerificationFailed = errors.New("attestation keyless verification failed")
	// )
	//
	// var (
	//	errCosignKeyVerificationFailed     = errors.New("cosign key-based signature verification failed")
	//	errCosignKeylessVerificationFailed = errors.New("cosign keyless signature verification failed")
)
