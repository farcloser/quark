package sigstore

import "errors"

var (
	errFailedReadingKey          = errors.New("failed to read key")
	errFailedCreatingVerifier    = errors.New("failed to create signature verifier")
	errFailedCreatingPolicy      = errors.New("failed to create signature identity policy")
	errKeyVerificationFailed     = errors.New("sigstore key-based signature verification failed")
	errKeylessVerificationFailed = errors.New("sigstore keyless signature verification failed")

	errUnrecognizedMediaType      = errors.New("unrecognized media type")
	errFailedParsingBundle        = errors.New("failed to parse bundle")
	errFailedParsingEnvelope      = errors.New("failed to parse envelope")
	errFailedParsingStatement     = errors.New("failed to parse statement")
	errUnrecognizedPredicateType  = errors.New("unrecognized predicate type")
	errFailedMarshallingPredicate = errors.New("failed to marshal predicate")

	errFailedParsingLegacySignature    = errors.New("failed to parse legacy signature")
	errFailedParsingLegacyAttestation = errors.New("failed to parse legacy attestation")
)
