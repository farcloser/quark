// Package sigstore provides OCI container image signature verification using sigstore-go.
package sigstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/rs/zerolog"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// VerificationResult contains the outcome of signature verification.
type VerificationResult struct {
	// Digest is the verified image digest (what was actually signed).
	Digest string

	// Signer contains the identity that signed the image.
	Signer SignerInfo
}

// SignerInfo contains information about the signer extracted from the certificate.
type SignerInfo struct {
	Subject string
	Issuer  string
}

// VerifyOptions contains options for signature verification.
type VerifyOptions struct {
	// ImageRef is the image reference to verify.
	ImageRef string

	// Digest is the expected digest (sha256:...).
	Digest string

	// RegistryAuth provides credentials for the registry.
	RegistryAuth *RegistryAuth

	// Logger for verification output.
	Log zerolog.Logger
}

// RegistryAuth contains registry credentials.
type RegistryAuth struct {
	Username string
	Password string
}

// fulcioIssuerOID is the OID for the Fulcio OIDC Issuer extension (1.3.6.1.4.1.57264.1.1).
//
//nolint:gochecknoglobals // OID constant defined at package level for clarity.
var fulcioIssuerOID = []int{1, 3, 6, 1, 4, 1, 57264, 1, 1}

// Signature verification errors.
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
)

// Verify verifies the cryptographic signature on a container image.
// Returns the verified digest and signer information on success.
// Note: This only verifies the signature is valid - caller must check if the signer is trusted.
func Verify(ctx context.Context, opts *VerifyOptions) (*VerificationResult, error) {
	opts.Log.Debug().
		Str("image", opts.ImageRef).
		Str("digest", opts.Digest).
		Msg("verifying image signature")

	// Build remote options.
	remoteOpts, craneOpts := buildRemoteOptions(ctx, opts.RegistryAuth)

	// 1. Fetch the signature from the registry.
	// This also validates that the payload contains the expected image digest.
	sigResult, err := fetchSignatureBundle(opts.ImageRef, opts.Digest, remoteOpts, craneOpts)
	if err != nil {
		return nil, err
	}

	// 2. Get trusted root from Sigstore's public good instance.
	trustedRoot, err := getTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted root: %w", err)
	}

	// 3. Create verifier.
	// Use transparency log for timestamp verification (Rekor).
	// - WithSignedCertificateTimestamps: verify Fulcio cert has SCT from CT log
	// - WithTransparencyLog: verify Rekor inclusion proof/SET
	// - WithIntegratedTimestamps: use Rekor log entry timestamp to verify cert validity
	verifierOpts := []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
	}

	signatureVerifier, err := verify.NewVerifier(trustedRoot, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	// 4. Create artifact policy with the payload bytes.
	// The signature covers the simple signing payload (which contains the image digest).
	// We already verified the payload contains the expected image digest in fetchSignatureBundle.
	artifactPolicy := verify.WithArtifact(bytes.NewReader(sigResult.PayloadBytes))

	// 5. Verify the bundle with any signer (identity check happens in SDK layer).
	// Use a permissive identity policy that accepts any valid Fulcio certificate.
	anySignerPolicy, err := verify.NewShortCertificateIdentity("", ".*", "", ".*")
	if err != nil {
		return nil, fmt.Errorf("failed to create permissive identity policy: %w", err)
	}

	result, err := signatureVerifier.Verify(sigResult.Bundle, verify.NewPolicy(
		artifactPolicy,
		verify.WithCertificateIdentity(anySignerPolicy),
	))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureVerificationFailed, err)
	}

	// 6. Extract signer info from the result.
	signerInfo := extractSignerInfo(result)

	opts.Log.Debug().
		Str("digest", "sha256:"+sigResult.ImageDigest).
		Str("signer_subject", signerInfo.Subject).
		Str("signer_issuer", signerInfo.Issuer).
		Msg("signature cryptographically valid")

	return &VerificationResult{
		Digest: "sha256:" + sigResult.ImageDigest,
		Signer: signerInfo,
	}, nil
}

// buildRemoteOptions constructs authentication options for registry operations.
func buildRemoteOptions(ctx context.Context, auth *RegistryAuth) ([]remote.Option, []crane.Option) {
	remoteOpts := []remote.Option{remote.WithContext(ctx)}
	craneOpts := []crane.Option{crane.WithContext(ctx)}

	if auth != nil && auth.Username != "" {
		basicAuth := &authn.Basic{
			Username: auth.Username,
			Password: auth.Password,
		}
		remoteOpts = append(remoteOpts, remote.WithAuth(basicAuth))
		craneOpts = append(craneOpts, crane.WithAuth(basicAuth))
	}

	return remoteOpts, craneOpts
}

// signatureBundleResult contains the fetched signature bundle and related data.
type signatureBundleResult struct {
	Bundle       *bundle.Bundle
	ImageDigest  string // The image digest (hex, without algorithm prefix)
	PayloadBytes []byte // The simple signing payload bytes (for verification)
}

// fetchSignatureBundle fetches the signature from the registry and builds a sigstore bundle.
func fetchSignatureBundle(
	imageRef, digest string,
	remoteOpts []remote.Option,
	craneOpts []crane.Option,
) (*signatureBundleResult, error) {
	// Parse the image reference.
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %w", err)
	}

	// If digest not provided, get it from the registry.
	if digest == "" {
		desc, err := remote.Get(ref, remoteOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to get image descriptor: %w", err)
		}

		digest = desc.Digest.String()
	}

	// Parse digest to get algorithm and hex.
	digestHash, err := v1.NewHash(digest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse digest: %w", err)
	}

	// Construct the signature reference: sha256-<hash>.sig.
	sigTag := ref.Context().Tag(fmt.Sprintf("%s-%s.sig", digestHash.Algorithm, digestHash.Hex))

	// Get the signature image to access layers.
	sigImage, err := crane.Pull(sigTag.Name(), craneOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSignatureFound, err)
	}

	// Get manifest to check layer metadata.
	sigManifest, err := sigImage.Manifest()
	if err != nil {
		return nil, fmt.Errorf("failed to get signature manifest: %w", err)
	}

	// Ensure there is at least one layer with the expected media type.
	if len(sigManifest.Layers) == 0 {
		return nil, fmt.Errorf("%w: no layers in signature manifest", ErrNoSignatureFound)
	}

	simpleSigning := &sigManifest.Layers[0]
	if simpleSigning.MediaType != "application/vnd.dev.cosign.simplesigning.v1+json" {
		return nil, fmt.Errorf(
			"%w: unexpected layer media type: %s",
			ErrInvalidSignatureFormat,
			simpleSigning.MediaType,
		)
	}

	// Fetch the actual simple signing payload blob.
	layers, err := sigImage.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to get signature layers: %w", err)
	}

	payloadReader, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("failed to read payload layer: %w", err)
	}
	defer payloadReader.Close()

	var payloadBuf bytes.Buffer
	if _, err := payloadBuf.ReadFrom(payloadReader); err != nil {
		return nil, fmt.Errorf("failed to read payload: %w", err)
	}

	payloadBytes := payloadBuf.Bytes()

	// Verify the payload contains the expected image digest.
	embeddedDigest, err := extractDigestFromPayload(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to extract digest from payload: %w", err)
	}

	if embeddedDigest != digest {
		return nil, fmt.Errorf(
			"%w: payload digest %s does not match expected %s",
			ErrSignatureVerificationFailed,
			embeddedDigest,
			digest,
		)
	}

	// Build verification material.
	verificationMaterial, err := buildVerificationMaterial(simpleSigning)
	if err != nil {
		return nil, fmt.Errorf("failed to build verification material: %w", err)
	}

	// Build message signature.
	msgSignature, err := buildMessageSignature(simpleSigning)
	if err != nil {
		return nil, fmt.Errorf("failed to build message signature: %w", err)
	}

	// Construct the bundle.
	bundleMediaType, err := bundle.MediaTypeString("0.1")
	if err != nil {
		return nil, fmt.Errorf("failed to get bundle media type: %w", err)
	}

	protoBundle := protobundle.Bundle{
		MediaType:            bundleMediaType,
		VerificationMaterial: verificationMaterial,
		Content:              msgSignature,
	}

	resultBundle, err := bundle.NewBundle(&protoBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to create bundle: %w", err)
	}

	return &signatureBundleResult{
		Bundle:       resultBundle,
		ImageDigest:  digestHash.Hex,
		PayloadBytes: payloadBytes,
	}, nil
}

// extractDigestFromPayload extracts the image digest from a simple signing payload.
// The payload format is: {"critical":{"image":{"docker-manifest-digest":"sha256:..."},...},...}.
func extractDigestFromPayload(payload []byte) (string, error) {
	// Local struct matches sigstore simple signing payload format.
	//nolint:tagliatelle // JSON field name is defined by sigstore spec, not our choice.
	var data struct {
		Critical struct { //nolint:revive // nested-structs: anonymous struct for one-time JSON parsing.
			Image struct { //nolint:revive // nested-structs: anonymous struct for one-time JSON parsing.
				DockerManifestDigest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
	}

	if err := json.Unmarshal(payload, &data); err != nil {
		return "", fmt.Errorf("failed to parse payload: %w", err)
	}

	if data.Critical.Image.DockerManifestDigest == "" {
		return "", ErrMissingDigestInPayload
	}

	return data.Critical.Image.DockerManifestDigest, nil
}

// buildVerificationMaterial extracts verification material from the signature layer.
func buildVerificationMaterial(layer *v1.Descriptor) (*protobundle.VerificationMaterial, error) {
	// Get X.509 certificate chain.
	certChain, err := extractCertificateChain(layer)
	if err != nil {
		return nil, fmt.Errorf("failed to extract certificate chain: %w", err)
	}

	// Get transparency log entries.
	tlogEntries, err := extractTlogEntries(layer)
	if err != nil {
		return nil, fmt.Errorf("failed to extract tlog entries: %w", err)
	}

	return &protobundle.VerificationMaterial{
		Content:     certChain,
		TlogEntries: tlogEntries,
	}, nil
}

// extractCertificateChain extracts the X.509 certificate chain from layer annotations.
func extractCertificateChain(layer *v1.Descriptor) (*protobundle.VerificationMaterial_X509CertificateChain, error) {
	pemCert, hasCert := layer.Annotations["dev.sigstore.cosign/certificate"]
	if !hasCert {
		return nil, ErrMissingCertificate
	}

	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, ErrInvalidPEM
	}

	// Verify it's a valid X.509 certificate.
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("invalid X.509 certificate: %w", err)
	}

	return &protobundle.VerificationMaterial_X509CertificateChain{
		X509CertificateChain: &protocommon.X509CertificateChain{
			Certificates: []*protocommon.X509Certificate{
				{RawBytes: block.Bytes},
			},
		},
	}, nil
}

// extractTlogEntries extracts transparency log entries from layer annotations.
func extractTlogEntries(layer *v1.Descriptor) ([]*protorekor.TransparencyLogEntry, error) {
	bundleAnnotation, hasBundle := layer.Annotations["dev.sigstore.cosign/bundle"]
	if !hasBundle {
		// No tlog entries - may be acceptable depending on policy.
		return nil, nil
	}

	var jsonData map[string]any
	if err := json.Unmarshal([]byte(bundleAnnotation), &jsonData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bundle annotation: %w", err)
	}

	payload, payloadOK := jsonData["Payload"].(map[string]any)
	if !payloadOK {
		return nil, ErrMissingPayload
	}

	logIndex, logIndexOK := payload["logIndex"].(float64)
	if !logIndexOK {
		return nil, ErrMissingLogIndex
	}

	logIDHex, logIDOK := payload["logID"].(string)
	if !logIDOK {
		return nil, ErrMissingLogID
	}

	logID, err := hex.DecodeString(logIDHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode logID: %w", err)
	}

	integratedTime, timeOK := payload["integratedTime"].(float64)
	if !timeOK {
		return nil, ErrMissingIntegratedTime
	}

	setB64, setOK := jsonData["SignedEntryTimestamp"].(string)
	if !setOK {
		return nil, ErrMissingTimestamp
	}

	signedEntryTimestamp, err := base64.StdEncoding.DecodeString(setB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SignedEntryTimestamp: %w", err)
	}

	bodyB64, bodyOK := payload["body"].(string)
	if !bodyOK {
		return nil, ErrMissingBody
	}

	bodyBytes, err := base64.StdEncoding.DecodeString(bodyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode body: %w", err)
	}

	// Extract kind version from body.
	var bodyJSON map[string]any
	if err := json.Unmarshal(bodyBytes, &bodyJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal body: %w", err)
	}

	apiVersion, _ := bodyJSON["apiVersion"].(string) //nolint:revive // optional field
	kind, _ := bodyJSON["kind"].(string)             //nolint:revive // optional field

	return []*protorekor.TransparencyLogEntry{
		{
			LogIndex: int64(logIndex),
			LogId: &protocommon.LogId{
				KeyId: logID,
			},
			KindVersion: &protorekor.KindVersion{
				Kind:    kind,
				Version: apiVersion,
			},
			IntegratedTime: int64(integratedTime),
			InclusionPromise: &protorekor.InclusionPromise{
				SignedEntryTimestamp: signedEntryTimestamp,
			},
			CanonicalizedBody: bodyBytes,
		},
	}, nil
}

// buildMessageSignature extracts the message signature from the layer.
func buildMessageSignature(layer *v1.Descriptor) (*protobundle.Bundle_MessageSignature, error) {
	// Get the signature.
	sigB64, hasSig := layer.Annotations["dev.cosignproject.cosign/signature"]
	if !hasSig {
		return nil, ErrMissingSignature
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Get digest algorithm.
	var hashAlg protocommon.HashAlgorithm

	switch layer.Digest.Algorithm {
	case "sha256":
		hashAlg = protocommon.HashAlgorithm_SHA2_256
	case "sha384":
		hashAlg = protocommon.HashAlgorithm_SHA2_384
	case "sha512":
		hashAlg = protocommon.HashAlgorithm_SHA2_512
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedDigestAlgorithm, layer.Digest.Algorithm)
	}

	digestBytes, err := hex.DecodeString(layer.Digest.Hex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode digest: %w", err)
	}

	return &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: hashAlg,
				Digest:    digestBytes,
			},
			Signature: sig,
		},
	}, nil
}

// getTrustedRoot fetches the Sigstore public good trusted root via TUF.
func getTrustedRoot() (root.TrustedMaterialCollection, error) {
	// Use Sigstore's public good TUF instance.
	client, err := tuf.New(tuf.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}

	trustedRootJSON, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted root: %w", err)
	}

	trustedRoot, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trusted root: %w", err)
	}

	return root.TrustedMaterialCollection{trustedRoot}, nil
}

// extractSignerInfo extracts signer information from the verification result.
func extractSignerInfo(result *verify.VerificationResult) SignerInfo {
	if result == nil || result.Signature == nil || result.Signature.Certificate == nil {
		return SignerInfo{}
	}

	cert := result.Signature.Certificate

	// certificate.Summary has SubjectAlternativeName and Issuer fields directly.
	return SignerInfo{
		Subject: cert.SubjectAlternativeName,
		Issuer:  cert.Issuer,
	}
}

// DiscoverSignerOptions contains options for discovering the signer of an image.
type DiscoverSignerOptions struct {
	// ImageRef is the image reference (e.g., "docker.io/library/alpine:3.20").
	ImageRef string

	// Digest is the image digest (sha256:...). If empty, will be resolved from registry.
	Digest string

	// RegistryAuth provides credentials for the registry.
	RegistryAuth *RegistryAuth

	// Logger for output.
	Log zerolog.Logger
}

// DiscoverSignerResult contains information about an image's signature.
type DiscoverSignerResult struct {
	// IsSigned indicates whether a signature was found for the image.
	IsSigned bool

	// Signer contains the identity that signed the image (only valid if IsSigned is true).
	Signer SignerInfo

	// Digest is the image digest the signature applies to.
	Digest string
}

// DiscoverSigner checks if an image is signed and extracts the signer identity
// WITHOUT requiring a trust policy. This allows users to discover who signed
// an image before deciding whether to trust them.
func DiscoverSigner(ctx context.Context, opts *DiscoverSignerOptions) (*DiscoverSignerResult, error) {
	opts.Log.Debug().
		Str("image", opts.ImageRef).
		Str("digest", opts.Digest).
		Msg("discovering image signer")

	// Build remote options.
	remoteOpts, craneOpts := buildRemoteOptions(ctx, opts.RegistryAuth)

	// Try to fetch the signature bundle.
	sigResult, err := fetchSignatureBundle(opts.ImageRef, opts.Digest, remoteOpts, craneOpts)
	if err != nil {
		// Check if it's "no signature found" vs. other error.
		if errors.Is(err, ErrNoSignatureFound) {
			return &DiscoverSignerResult{
				IsSigned: false,
				Digest:   opts.Digest,
			}, nil
		}

		return nil, err
	}

	// Extract signer info from the bundle's certificate (without verification).
	signerInfo, err := extractSignerFromBundle(sigResult.Bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to extract signer from bundle: %w", err)
	}

	return &DiscoverSignerResult{
		IsSigned: true,
		Signer:   signerInfo,
		Digest:   "sha256:" + sigResult.ImageDigest,
	}, nil
}

// extractSignerFromBundle extracts signer information directly from the bundle's certificate
// without performing full verification.
func extractSignerFromBundle(b *bundle.Bundle) (SignerInfo, error) {
	// Get verification content which provides access to the certificate.
	verificationContent, err := b.VerificationContent()
	if err != nil {
		return SignerInfo{}, fmt.Errorf("failed to get verification content: %w", err)
	}

	cert := verificationContent.Certificate()
	if cert == nil {
		return SignerInfo{}, ErrNoCertificateInBundle
	}

	// Extract subject from certificate extensions (Fulcio SAN).
	subject := extractSubjectFromCert(cert)

	// Extract issuer from certificate extensions (Fulcio OIDC issuer).
	issuer := extractIssuerFromCert(cert)

	return SignerInfo{
		Subject: subject,
		Issuer:  issuer,
	}, nil
}

// extractSubjectFromCert extracts the subject (email or URI) from a Fulcio certificate.
func extractSubjectFromCert(cert *x509.Certificate) string {
	// Check email addresses first (common for personal signing).
	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0]
	}

	// Check URIs (used for workload identity / GitHub Actions).
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}

	// Fallback to subject common name.
	return cert.Subject.CommonName
}

// extractIssuerFromCert extracts the OIDC issuer from a Fulcio certificate.
// The issuer is stored in a custom extension (OID 1.3.6.1.4.1.57264.1.1).
func extractIssuerFromCert(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if oidEquals(ext.Id, fulcioIssuerOID) {
			// The issuer is stored as a raw string or ASN.1 UTF8String.
			return string(ext.Value)
		}
	}

	// Fallback: check issuer common name.
	return cert.Issuer.CommonName
}

// oidEquals checks if two OIDs are equal.
func oidEquals(oid1, oid2 []int) bool {
	if len(oid1) != len(oid2) {
		return false
	}

	for i := range oid1 {
		if oid1[i] != oid2[i] {
			return false
		}
	}

	return true
}
