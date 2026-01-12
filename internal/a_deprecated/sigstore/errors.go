package sigstore

import "errors"

// Signing and attestation errors.
var (
	// ErrNoSigningMethod indicates neither OIDC nor private key was provided.
	ErrNoSigningMethod = errors.New("no signing method configured: provide OIDC token or private key")
	// ErrSigningFailed indicates the signing operation failed.
	ErrSigningFailed = errors.New("signing failed")
	// ErrAttestFailed indicates the attestation operation failed.
	ErrAttestFailed = errors.New("attestation failed")
	// ErrInvalidPrivateKey indicates the private key could not be parsed.
	ErrInvalidPrivateKey = errors.New("invalid private key")
	// ErrFulcioCertificateFailed indicates Fulcio certificate retrieval failed.
	ErrFulcioCertificateFailed = errors.New("failed to get Fulcio certificate")
	// ErrRekorUploadFailed indicates transparency log upload failed.
	ErrRekorUploadFailed = errors.New("failed to upload to transparency log")
	// ErrRekorEmptyResponse indicates Rekor returned an empty response.
	ErrRekorEmptyResponse = errors.New("empty response from Rekor")
	// ErrRekorUnexpectedBody indicates the Rekor response body was not a string.
	ErrRekorUnexpectedBody = errors.New("unexpected Rekor response body type")
	// ErrCreateEphemeralKeypair indicates ephemeral keypair creation failed.
	ErrCreateEphemeralKeypair = errors.New("failed to create ephemeral keypair")
	// ErrSignPayload indicates payload signing failed.
	ErrSignPayload = errors.New("failed to sign payload")
	// ErrSign indicates signing operation failed.
	ErrSign = errors.New("failed to sign")
	// ErrEncodePublicKey indicates public key encoding failed.
	ErrEncodePublicKey = errors.New("failed to encode public key")
	// ErrCreateSignatureImage indicates signature image creation failed.
	ErrCreateSignatureImage = errors.New("failed to create signature image")
	// ErrPushSignature indicates signature push to registry failed.
	ErrPushSignature = errors.New("failed to push signature")
	// ErrCreateLogEntry indicates Rekor log entry creation failed.
	ErrCreateLogEntry = errors.New("failed to create log entry")
	// ErrPushAttestation indicates attestation push to registry failed.
	ErrPushAttestation = errors.New("failed to push attestation")
	// ErrInvalidDigestFormat indicates an invalid digest format was provided.
	ErrInvalidDigestFormat = errors.New("invalid digest format")
	// ErrMarshalVEX indicates VEX document marshaling failed.
	ErrMarshalVEX = errors.New("failed to marshal VEX document")
	// ErrNilTlogEntry indicates a nil transparency log entry was provided.
	ErrNilTlogEntry = errors.New("nil transparency log entry")
	// ErrDecodePEMBlock indicates PEM block decoding failed.
	ErrDecodePEMBlock = errors.New("failed to decode PEM block")
	// ErrKeyNotSigner indicates the key does not implement crypto.Signer.
	ErrKeyNotSigner = errors.New("key does not implement crypto.Signer")
	// ErrUnsupportedKeyFormat indicates an unsupported key format.
	ErrUnsupportedKeyFormat = errors.New("unsupported key format")
	// ErrNoDSSEEnvelope indicates the bundle does not contain a DSSE envelope.
	ErrNoDSSEEnvelope = errors.New("bundle does not contain DSSE envelope")
)

// Verification errors.
var (
	// ErrNoSignatureFound indicates no signature artifact was found for the image.
	ErrNoSignatureFound = errors.New("no signature found for image")
	// ErrSignatureVerificationFailed indicates the signature failed cryptographic verification.
	ErrSignatureVerificationFailed = errors.New("signature verification failed")
	// ErrSignerNotTrusted indicates the signer identity doesn't match any trusted identity.
	ErrSignerNotTrusted = errors.New("signer not trusted")
	// ErrInvalidSignatureFormat indicates the signature has an invalid format.
	ErrInvalidSignatureFormat = errors.New("invalid signature format")
	// ErrMissingCertificate indicates certificate annotation is missing.
	ErrMissingCertificate = errors.New("missing certificate annotation")
	// ErrInvalidPEM indicates PEM certificate decoding failed.
	ErrInvalidPEM = errors.New("failed to decode PEM certificate")
	// ErrMissingPayload indicates Payload field is missing from bundle.
	ErrMissingPayload = errors.New("missing Payload in bundle")
	// ErrMissingLogIndex indicates logIndex field is missing.
	ErrMissingLogIndex = errors.New("missing logIndex")
	// ErrMissingLogID indicates logID field is missing.
	ErrMissingLogID = errors.New("missing logID")
	// ErrMissingIntegratedTime indicates integratedTime field is missing.
	ErrMissingIntegratedTime = errors.New("missing integratedTime")
	// ErrMissingTimestamp indicates SignedEntryTimestamp field is missing.
	ErrMissingTimestamp = errors.New("missing SignedEntryTimestamp")
	// ErrMissingBody indicates body field is missing.
	ErrMissingBody = errors.New("missing body")
	// ErrMissingSignature indicates signature annotation is missing.
	ErrMissingSignature = errors.New("missing signature annotation")
	// ErrUnsupportedDigestAlgorithm indicates an unsupported digest algorithm.
	ErrUnsupportedDigestAlgorithm = errors.New("unsupported digest algorithm")
	// ErrNoCertificateInBundle indicates the bundle has no certificate.
	ErrNoCertificateInBundle = errors.New("no certificate in bundle")
	// ErrMissingDigestInPayload indicates docker-manifest-digest is missing from signature payload.
	ErrMissingDigestInPayload = errors.New("missing docker-manifest-digest in payload")
	// ErrGetImageDescriptor indicates failure to get an image descriptor from registry.
	ErrGetImageDescriptor = errors.New("failed to get image descriptor")
	// ErrParseDigest indicates failure to parse an image digest.
	ErrParseDigest = errors.New("failed to parse digest")
	// ErrGetSignatureManifest indicates failure to get signature manifest.
	ErrGetSignatureManifest = errors.New("failed to get signature manifest")
	// ErrNoLayersInSignature indicates the signature manifest has no layers.
	ErrNoLayersInSignature = errors.New("no layers in signature manifest")
	// ErrGetTrustedRoot indicates failure to get trusted root.
	ErrGetTrustedRoot = errors.New("failed to get trusted root")
	// ErrCreateVerifier indicates failure to create verifier.
	ErrCreateVerifier = errors.New("failed to create verifier")
	// ErrCreateIdentityPolicy indicates failure to create identity policy.
	ErrCreateIdentityPolicy = errors.New("failed to create permissive identity policy")
	// ErrParsePublicKey indicates failure to parse public key.
	ErrParsePublicKey = errors.New("failed to parse public key")
	// ErrLoadVerifier indicates failure to load verifier.
	ErrLoadVerifier = errors.New("failed to load verifier")
	// ErrGetSignatureLayers indicates failure to get signature layers.
	ErrGetSignatureLayers = errors.New("failed to get signature layers")
	// ErrReadPayloadLayer indicates failure to read payload layer.
	ErrReadPayloadLayer = errors.New("failed to read payload layer")
	// ErrReadPayload indicates failure to read payload.
	ErrReadPayload = errors.New("failed to read payload")
	// ErrExtractDigestFromPayload indicates failure to extract digest from payload.
	ErrExtractDigestFromPayload = errors.New("failed to extract digest from payload")
	// ErrDecodeSignature indicates failure to decode signature.
	ErrDecodeSignature = errors.New("failed to decode signature")
	// ErrBuildVerificationMaterial indicates failure to build verification material.
	ErrBuildVerificationMaterial = errors.New("failed to build verification material")
	// ErrBuildMessageSignature indicates failure to build message signature.
	ErrBuildMessageSignature = errors.New("failed to build message signature")
	// ErrGetBundleMediaType indicates failure to get bundle media type.
	ErrGetBundleMediaType = errors.New("failed to get bundle media type")
	// ErrCreateBundle indicates failure to create bundle.
	ErrCreateBundle = errors.New("failed to create bundle")
	// ErrParsePayload indicates failure to parse payload.
	ErrParsePayload = errors.New("failed to parse payload")
	// ErrExtractCertificateChain indicates failure to extract certificate chain.
	ErrExtractCertificateChain = errors.New("failed to extract certificate chain")
	// ErrExtractTlogEntries indicates failure to extract tlog entries.
	ErrExtractTlogEntries = errors.New("failed to extract tlog entries")
	// ErrInvalidX509Certificate indicates invalid X.509 certificate.
	ErrInvalidX509Certificate = errors.New("invalid X.509 certificate")
	// ErrUnmarshalBundleAnnotation indicates failure to unmarshal bundle annotation.
	ErrUnmarshalBundleAnnotation = errors.New("failed to unmarshal bundle annotation")
	// ErrDecodeLogID indicates failure to decode logID.
	ErrDecodeLogID = errors.New("failed to decode logID")
	// ErrDecodeTimestamp indicates failure to decode SignedEntryTimestamp.
	ErrDecodeTimestamp = errors.New("failed to decode SignedEntryTimestamp")
	// ErrDecodeBody indicates failure to decode body.
	ErrDecodeBody = errors.New("failed to decode body")
	// ErrUnmarshalBody indicates failure to unmarshal body.
	ErrUnmarshalBody = errors.New("failed to unmarshal body")
	// ErrDecodeDigest indicates failure to decode digest.
	ErrDecodeDigest = errors.New("failed to decode digest")
	// ErrCreateTUFClient indicates failure to create TUF client.
	ErrCreateTUFClient = errors.New("failed to create TUF client")
	// ErrParseTrustedRoot indicates failure to parse trusted root.
	ErrParseTrustedRoot = errors.New("failed to parse trusted root")
	// ErrExtractKeylessSigner indicates failure to extract keyless signer from bundle.
	ErrExtractKeylessSigner = errors.New("failed to extract keyless signer from bundle")
	// ErrGetVerificationContent indicates failure to get verification content.
	ErrGetVerificationContent = errors.New("failed to get verification content")
	// ErrHashMismatch indicates the digest in signature doesn't match expected digest.
	ErrHashMismatch = errors.New("digest in signature does not match expected digest")
	// ErrSignatureTagMismatch indicates multiple signatures have different tags.
	ErrSignatureTagMismatch = errors.New("multiple signatures with different tags detected")
)

// Attestation inspection errors.
var (
	// ErrParseAttestationTag indicates failure to parse attestation tag reference.
	ErrParseAttestationTag = errors.New("failed to parse attestation tag")
	// ErrGetAttestationManifest indicates failure to get attestation manifest.
	ErrGetAttestationManifest = errors.New("failed to get attestation manifest")
	// ErrGetAttestationLayers indicates failure to get attestation layers.
	ErrGetAttestationLayers = errors.New("failed to get attestation layers")
	// ErrReadAttestationLayer indicates failure to read attestation layer.
	ErrReadAttestationLayer = errors.New("failed to read attestation layer")
	// ErrReadAttestationContent indicates failure to read attestation content.
	ErrReadAttestationContent = errors.New("failed to read attestation content")
	// ErrParseDSSEEnvelope indicates failure to parse DSSE envelope.
	ErrParseDSSEEnvelope = errors.New("failed to parse DSSE envelope")
	// ErrDecodeAttestationPayload indicates failure to decode attestation payload.
	ErrDecodeAttestationPayload = errors.New("failed to decode attestation payload")
	// ErrParseInTotoStatement indicates failure to parse in-toto statement.
	ErrParseInTotoStatement = errors.New("failed to parse in-toto statement")
)
