package sigstore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/trust"
	"github.com/farcloser/quark/internal/a_deprecated/registry"
	"github.com/farcloser/quark/internal/types"
	"github.com/google/go-containerregistry/pkg/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	sigstoresig "github.com/sigstore/sigstore/pkg/signature"

	"github.com/farcloser/quark/internal/reference"
)

// VerificationResult contains the outcome of signature verification.
type VerificationResult struct {
	// Digest is the verified image digest (what was actually signed).
	Digest string

	// Keyless contains identity info if this is a keyless (Fulcio) signature.
	// Nil if the signature is key-based.
	Keyless *types.KeylessSignerInfo

	// IsKeyBased is true if the signature was made with a private key (no certificate).
	IsKeyBased bool

	// Annotations are custom key-value pairs attached to the signature.
	Annotations map[string]string
}

// VerifyWithKeyOptions contains options for key-based signature verification.
type VerifyWithKeyOptions struct {
	// ImageRef is the parsed image reference to verify.
	ImageRef reference.ImageReference

	// Digest is the expected digest (sha256:...).
	Digest string

	// PublicKey is the PEM-encoded public key to verify against.
	PublicKey []byte

	// RegistryClient is the registry client for fetching signature artifacts.
	RegistryClient *registry.Client

	// Logger for verification output.
	Log *slog.Logger
}

// VerifyOptions contains options for signature verification.
type VerifyOptions struct {
	// ImageRef is the parsed image reference to verify.
	ImageRef reference.ImageReference

	// Digest is the expected digest (sha256:...).
	Digest string

	// RegistryClient is the registry client for fetching signature artifacts.
	RegistryClient *registry.Client

	// Logger for verification output.
	Log *slog.Logger
}

// fulcioIssuerOID is the OID for the Fulcio OIDC Issuer extension (1.3.6.1.4.1.57264.1.1).
//
//nolint:gochecknoglobals // OID constant defined at package level for clarity.
var fulcioIssuerOID = []int{1, 3, 6, 1, 4, 1, 57264, 1, 1}

const (
	sigTagFormat          = "%s:%s-%s.sig"
	digestAlgorithmPrefix = "sha256:"
	certAnnotation        = "dev.sigstore.cosign/certificate"
)

// reservedAnnotationPrefixes are annotation prefixes used by sigstore/cosign internally.
// These are filtered out when extracting custom user annotations.
//
//nolint:gochecknoglobals // Package-level constant for annotation filtering.
var reservedAnnotationPrefixes = []string{
	"dev.cosignproject.cosign/",
	"dev.sigstore.cosign/",
}

// extractCustomAnnotations filters out sigstore-reserved annotations and returns only custom ones.
func extractCustomAnnotations(annotations map[string]string) map[string]string {
	if len(annotations) == 0 {
		return nil
	}

	custom := make(map[string]string)

	for key, value := range annotations {
		isReserved := false

		for _, prefix := range reservedAnnotationPrefixes {
			if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
				isReserved = true

				break
			}
		}

		if !isReserved {
			custom[key] = value
		}
	}

	if len(custom) == 0 {
		return nil
	}

	return custom
}

// Verify verifies the cryptographic signature on a container image.
// Returns the verified digest and signer information on success.
// Note: This only verifies the signature is valid - caller must check if the signer is trusted.
func Verify(ctx context.Context, opts *VerifyOptions) (*VerificationResult, error) {
	opts.Log.DebugContext(ctx, "verifying image signature",
		"image", opts.ImageRef.String(), //revive:disable-line:add-constant
		"digest", opts.Digest) //revive:disable-line:add-constant

	// 1. Fetch the signature from the registry.
	// This also validates that the payload contains the expected image digest.
	sigResult, err := fetchSignatureBundle(ctx, opts.RegistryClient, opts.ImageRef, opts.Digest)
	if err != nil {
		return nil, err
	}

	// 2. Get trusted root from Sigstore's public good instance.
	trustedRoot, err := getTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetTrustedRoot, err)
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
		return nil, fmt.Errorf("%w: %w", ErrCreateVerifier, err)
	}

	// 4. Create artifact policy with the payload bytes.
	// The signature covers the simple signing payload (which contains the image digest).
	// We already verified the payload contains the expected image digest in fetchSignatureBundle.
	artifactPolicy := verify.WithArtifact(bytes.NewReader(sigResult.PayloadBytes))

	// 5. Verify the bundle with any signer (identity check happens in SDK layer).
	// Use a permissive identity policy that accepts any valid Fulcio certificate.
	anySignerPolicy, err := verify.NewShortCertificateIdentity("", ".*", "", ".*")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCreateIdentityPolicy, err)
	}

	result, err := signatureVerifier.Verify(sigResult.Bundle, verify.NewPolicy(
		artifactPolicy,
		verify.WithCertificateIdentity(anySignerPolicy),
	))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureVerificationFailed, err)
	}

	// 6. Extract signer info from the result.
	keylessInfo := extractKeylessSignerInfo(result)

	opts.Log.DebugContext(ctx, "signature cryptographically valid",
		"digest", "sha256:"+sigResult.ImageDigest, //revive:disable-line:add-constant
		"signer_subject", keylessInfo.Subject,
		"signer_issuer", keylessInfo.Issuer)

	return &VerificationResult{
		Digest:      digestAlgorithmPrefix + sigResult.ImageDigest,
		Keyless:     keylessInfo,
		IsKeyBased:  false,
		Annotations: sigResult.Annotations,
	}, nil
}

// VerifyWithPublicKey verifies a key-based signature against a provided public key.
// This is for images signed with cosign using a private key (not keyless/Fulcio).
// Uses github.com/sigstore/sigstore for signature verification.
func VerifyWithPublicKey(ctx context.Context, opts *VerifyWithKeyOptions) (*VerificationResult, error) {
	opts.Log.DebugContext(ctx, "verifying key-based signature",
		"image", opts.ImageRef.String(), //revive:disable-line:add-constant
		"digest", opts.Digest) //revive:disable-line:add-constant

	// 1. Fetch the signature from the registry.
	sigResult, err := fetchSignatureForKeyVerification(ctx, opts.RegistryClient, opts.ImageRef, opts.Digest)
	if err != nil {
		return nil, err
	}

	// 2. Parse the public key using sigstore cryptoutils.
	pubKey, err := trust.PEMToPublicKey(opts.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParsePublicKey, err)
	}

	// 3. Create verifier using sigstore signature package.
	verifier, err := sigstoresig.LoadVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLoadVerifier, err)
	}

	// 4. Verify the signature over the payload.
	// The signature is already base64-decoded in sigResult.
	if err := verifier.VerifySignature(
		bytes.NewReader(sigResult.Signature),
		bytes.NewReader(sigResult.PayloadBytes),
	); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignatureVerificationFailed, err)
	}

	opts.Log.DebugContext(ctx, "key-based signature cryptographically valid", //revive:disable-line:add-constant
		"digest", "sha256:"+sigResult.ImageDigest)

	return &VerificationResult{
		Digest:      digestAlgorithmPrefix + sigResult.ImageDigest,
		Keyless:     nil,
		IsKeyBased:  true,
		Annotations: sigResult.Annotations,
	}, nil
}

// keyBasedSignatureResult contains data needed for key-based signature verification.
type keyBasedSignatureResult struct {
	ImageDigest  string            // The image digest (hex, without algorithm prefix)
	PayloadBytes []byte            // The simple signing payload bytes (for verification)
	Signature    []byte            // The decoded signature bytes
	Annotations  map[string]string // Custom annotations attached to the signature
}

// fetchSignatureForKeyVerification fetches signature data needed for key-based verification.
func fetchSignatureForKeyVerification(
	ctx context.Context,
	client *registry.Client,
	imageRef reference.ImageReference,
	dgst string,
) (*keyBasedSignatureResult, error) {
	// If dgst not provided, get it from the registry.
	if dgst == "" {
		var err error

		dgst, err = client.GetDigest(ctx, imageRef)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrGetImageDescriptor, err)
		}
	}

	digDigest := types.Digest(dgst)

	// Construct the signature reference: sha256-<hash>.sig.
	sigTagStr := fmt.Sprintf(sigTagFormat,
		imageRef.Name(),
		digDigest.Algorithm(),
		digDigest.Hex())

	sigRef, err := reference.Parse(sigTagStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSignatureFound, err)
	}

	// Get the signature image to access layers.
	sigImage, err := client.GetImageHandle(ctx, *sigRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSignatureFound, err)
	}

	// Get manifest to check layer metadata.
	sigManifest, err := sigImage.Manifest()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetSignatureManifest, err)
	}

	// Ensure there is at least one layer.
	if len(sigManifest.Layers) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrNoSignatureFound, ErrNoLayersInSignature)
	}

	simpleSigning := &sigManifest.Layers[0]

	// Fetch the actual simple signing payload blob.
	layers, err := sigImage.Layers()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetSignatureLayers, err)
	}

	payloadReader, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadPayloadLayer, err)
	}
	defer payloadReader.Close()

	var payloadBuf bytes.Buffer
	if _, err := payloadBuf.ReadFrom(payloadReader); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadPayload, err)
	}

	payloadBytes := payloadBuf.Bytes()

	// Verify the payload contains the expected image dgst.
	embeddedDigest, err := extractDigestFromPayload(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExtractDigestFromPayload, err)
	}

	if embeddedDigest != dgst {
		return nil, fmt.Errorf(
			"%w: payload dgst %s does not match expected %s",
			ErrSignatureVerificationFailed,
			embeddedDigest,
			dgst,
		)
	}

	// Get the signature from annotations.
	sigB64, hasSig := simpleSigning.Annotations["dev.cosignproject.cosign/signature"]
	if !hasSig {
		return nil, ErrMissingSignature
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeSignature, err)
	}

	// Extract custom annotations (filter out sigstore-reserved ones).
	customAnnotations := extractCustomAnnotations(simpleSigning.Annotations)

	return &keyBasedSignatureResult{
		ImageDigest:  digDigest.Hex(),
		PayloadBytes: payloadBytes,
		Signature:    sig,
		Annotations:  customAnnotations,
	}, nil
}

// signatureBundleResult contains the fetched signature bundle and related data.
type signatureBundleResult struct {
	Bundle         *bundle.Bundle
	ImageDigest    string            // The image digest (hex, without algorithm prefix)
	PayloadBytes   []byte            // The simple signing payload bytes (for verification)
	HasCertificate bool              // True if the signature has a Fulcio certificate (keyless)
	Annotations    map[string]string // Custom annotations attached to the signature
}

// fetchSignatureBundle fetches the signature from the registry and builds a sigstore bundle.
func fetchSignatureBundle(
	ctx context.Context,
	client *registry.Client,
	imageRef reference.ImageReference,
	dgst string,
) (*signatureBundleResult, error) {
	digDigest := types.Digest(dgst)

	// Construct the signature reference: sha256-<hash>.sig.
	sigTagStr := fmt.Sprintf(sigTagFormat,
		imageRef.Name(),
		digDigest.Algorithm(),
		digDigest.Hex())

	sigRef, err := reference.Parse(sigTagStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSignatureFound, err)
	}

	// Get the signature image to access layers.
	sigImage, err := client.GetImageHandle(ctx, *sigRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSignatureFound, err)
	}

	// Get manifest to check layer metadata.
	sigManifest, err := sigImage.Manifest()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetSignatureManifest, err)
	}

	// Ensure there is at least one layer with the expected media type.
	if len(sigManifest.Layers) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrNoSignatureFound, ErrNoLayersInSignature)
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
		return nil, fmt.Errorf("%w: %w", ErrGetSignatureLayers, err)
	}

	payloadReader, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadPayloadLayer, err)
	}
	defer payloadReader.Close()

	var payloadBuf bytes.Buffer
	if _, err := payloadBuf.ReadFrom(payloadReader); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadPayload, err)
	}

	payloadBytes := payloadBuf.Bytes()

	// Verify the payload contains the expected image dgst.
	embeddedDigest, err := extractDigestFromPayload(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExtractDigestFromPayload, err)
	}

	if embeddedDigest != dgst {
		return nil, fmt.Errorf(
			"%w: payload dgst %s does not match expected %s",
			ErrSignatureVerificationFailed,
			embeddedDigest,
			dgst,
		)
	}

	// Build verification material.
	verificationMaterial, err := buildVerificationMaterial(simpleSigning)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBuildVerificationMaterial, err)
	}

	// Build message signature.
	msgSignature, err := buildMessageSignature(simpleSigning)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBuildMessageSignature, err)
	}

	// Construct the bundle.
	bundleMediaType, err := bundle.MediaTypeString("0.1")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetBundleMediaType, err)
	}

	protoBundle := protobundle.Bundle{
		MediaType:            bundleMediaType,
		VerificationMaterial: verificationMaterial,
		Content:              msgSignature,
	}

	resultBundle, err := bundle.NewBundle(&protoBundle)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCreateBundle, err)
	}

	// Check if certificate is present.
	_, hasCert := simpleSigning.Annotations[certAnnotation]

	// Extract custom annotations (filter out sigstore-reserved ones).
	customAnnotations := extractCustomAnnotations(simpleSigning.Annotations)

	return &signatureBundleResult{
		Bundle:         resultBundle,
		ImageDigest:    digDigest.Hex(),
		PayloadBytes:   payloadBytes,
		HasCertificate: hasCert,
		Annotations:    customAnnotations,
	}, nil
}

// signatureInfoResult contains minimal signature information for inspection.
type signatureInfoResult struct {
	ImageDigest    string            // The image digest (hex, without algorithm prefix)
	HasCertificate bool              // True if the signature has a Fulcio certificate (keyless)
	Bundle         *bundle.Bundle    // Only populated for keyless signatures
	Annotations    map[string]string // Custom annotations attached to the signature
}

// fetchSignatureInfo fetches basic signature information without full bundle construction.
// This is used for inspection where we just need to know if a signature exists and its type.
func fetchSignatureInfo(
	ctx context.Context,
	client *registry.Client,
	imageRef reference.ImageReference,
	dgst string,
) (*signatureInfoResult, error) {
	// If dgst not provided, get it from the registry.
	if dgst == "" {
		var err error

		dgst, err = client.GetDigest(ctx, imageRef)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrGetImageDescriptor, err)
		}
	}

	digDigest := types.Digest(dgst)

	// Construct the signature reference: sha256-<hash>.sig.
	sigTagStr := fmt.Sprintf(sigTagFormat,
		imageRef.Name(),
		digDigest.Algorithm(),
		digDigest.Hex())

	sigRef, err := reference.Parse(sigTagStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSignatureFound, err)
	}

	// Get the signature image to access layers.
	sigImage, err := client.GetImageHandle(ctx, *sigRef)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSignatureFound, err)
	}

	// Get manifest to check layer metadata.
	sigManifest, err := sigImage.Manifest()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetSignatureManifest, err)
	}

	// Ensure there is at least one layer.
	if len(sigManifest.Layers) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrNoSignatureFound, ErrNoLayersInSignature)
	}

	simpleSigning := &sigManifest.Layers[0]

	// Check if certificate is present (keyless) or not (key-based).
	_, hasCert := simpleSigning.Annotations[certAnnotation]

	// Extract custom annotations (filter out sigstore-reserved ones).
	customAnnotations := extractCustomAnnotations(simpleSigning.Annotations)

	result := &signatureInfoResult{
		ImageDigest:    digDigest.Hex(),
		HasCertificate: hasCert,
		Annotations:    customAnnotations,
	}

	// For keyless signatures, build the full bundle to extract signer info.
	if hasCert {
		bundleResult, err := fetchSignatureBundle(ctx, client, imageRef, dgst)
		if err != nil {
			return nil, err
		}

		result.Bundle = bundleResult.Bundle
	}

	return result, nil
}

// extractDigestFromPayload extracts the image digest from a simple signing payload.
// The payload format is: {"critical":{"image":{"docker-manifest-digest":"sha256:..."},...},...}.
func extractDigestFromPayload(payload []byte) (string, error) {
	// Local struct matches sigstore simple signing payload format.
	//nolint:tagliatelle // JSON field name is defined by sigstore spec, not our choice.
	var data struct {
		Critical struct { //revive:disable:nested-structs // anonymous struct for one-time JSON parsing.
			Image struct { //revive:disable:nested-structs // anonymous struct for one-time JSON parsing.
				DockerManifestDigest string `json:"docker-manifest-digest"`
			} `json:"image"`
		} `json:"critical"`
	}

	if err := json.Unmarshal(payload, &data); err != nil {
		return "", fmt.Errorf("%w: %w", ErrParsePayload, err)
	}

	if data.Critical.Image.DockerManifestDigest == "" {
		return "", ErrMissingDigestInPayload
	}

	return data.Critical.Image.DockerManifestDigest, nil
}

// buildVerificationMaterial extracts verification material from the signature layer.
func buildVerificationMaterial(layer *v1.Descriptor) (*protobundle.VerificationMaterial, error) {
	// Get X.509 certificate chain.
	certChain, err := extractCertificateChain(layer.Annotations)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExtractCertificateChain, err)
	}

	// Get transparency log entries.
	tlogEntries, err := extractTlogEntries(layer)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExtractTlogEntries, err)
	}

	return &protobundle.VerificationMaterial{
		Content:     certChain,
		TlogEntries: tlogEntries,
	}, nil
}

// extractCertificateChain extracts the X.509 certificate chain from layer annotations.
func extractCertificateChain(annotations map[string]string) (*protobundle.VerificationMaterial_X509CertificateChain, error) {
	pemCert, hasCert := annotations[certAnnotation]
	if !hasCert {
		return nil, ErrMissingCertificate
	}

	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, ErrInvalidPEM
	}

	// Verify it's a valid X.509 certificate.
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidX509Certificate, err)
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
		return nil, fmt.Errorf("%w: %w", ErrUnmarshalBundleAnnotation, err)
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
		return nil, fmt.Errorf("%w: %w", ErrDecodeLogID, err)
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
		return nil, fmt.Errorf("%w: %w", ErrDecodeTimestamp, err)
	}

	bodyB64, bodyOK := payload["body"].(string)
	if !bodyOK {
		return nil, ErrMissingBody
	}

	bodyBytes, err := base64.StdEncoding.DecodeString(bodyB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeBody, err)
	}

	// Extract kind version from body.
	var bodyJSON map[string]any
	if err := json.Unmarshal(bodyBytes, &bodyJSON); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnmarshalBody, err)
	}

	apiVersion, _ := bodyJSON["apiVersion"].(string) //revive:disable-line:unchecked-type-assertion // optional field
	kind, _ := bodyJSON["kind"].(string)             //revive:disable-line:unchecked-type-assertion // optional field

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
		return nil, fmt.Errorf("%w: %w", ErrDecodeSignature, err)
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
		return nil, fmt.Errorf("%w: %w", ErrDecodeDigest, err)
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
		return nil, fmt.Errorf("%w: %w", ErrCreateTUFClient, err)
	}

	trustedRootJSON, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetTrustedRoot, err)
	}

	trustedRoot, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseTrustedRoot, err)
	}

	return root.TrustedMaterialCollection{trustedRoot}, nil
}

// extractKeylessSignerInfo extracts keyless signer information from the verification result.
func extractKeylessSignerInfo(result *verify.VerificationResult) *types.KeylessSignerInfo {
	if result == nil || result.Signature == nil || result.Signature.Certificate == nil {
		return nil
	}

	cert := result.Signature.Certificate

	// certificate.Summary has SubjectAlternativeName and Issuer fields directly.
	return &types.KeylessSignerInfo{
		Subject: cert.SubjectAlternativeName,
		Issuer:  cert.Issuer,
	}
}

// InspectOptions contains options for inspecting an image signature.
type InspectOptions struct {
	// ImageRef is the parsed image reference.
	ImageRef reference.ImageReference

	// Digest is the image digest (sha256:...). If empty, will be resolved from registry.
	Digest string

	// RegistryClient is the registry client for fetching signature artifacts.
	RegistryClient *registry.Client

	// Logger for output.
	Log *slog.Logger
}

// InspectResult contains information about an image's signature.
type InspectResult struct {
	// IsSigned indicates whether a signature was found for the image.
	IsSigned bool

	// Digest is the image digest the signature applies to.
	Digest string

	// Keyless contains identity info if this is a keyless (Fulcio) signature.
	// Nil if the signature is key-based or unsigned.
	Keyless *types.KeylessSignerInfo

	// IsKeyBased is true if the signature was made with a private key (no certificate).
	IsKeyBased bool

	// Annotations are custom key-value pairs attached to the signature.
	Annotations map[string]string
}

// Inspect checks if an image is signed and extracts signature information
// WITHOUT requiring a trust policy. This allows users to discover what kind
// of signature exists before deciding whether to trust it.
func Inspect(ctx context.Context, opts *InspectOptions) (*InspectResult, error) {
	opts.Log.DebugContext(ctx, "inspecting image signature",
		"image", opts.ImageRef.String(), //revive:disable-line:add-constant
		"digest", opts.Digest) //revive:disable-line:add-constant

	// Try to fetch the signature.
	sigResult, err := fetchSignatureInfo(ctx, opts.RegistryClient, opts.ImageRef, opts.Digest)
	if err != nil {
		// Check if it's "no signature found" vs. other error.
		if errors.Is(err, ErrNoSignatureFound) {
			return &InspectResult{
				IsSigned: false,
				Digest:   opts.Digest,
			}, nil
		}

		return nil, err
	}

	result := &InspectResult{
		IsSigned:    true,
		Digest:      digestAlgorithmPrefix + sigResult.ImageDigest,
		Keyless:     nil,
		IsKeyBased:  true,
		Annotations: sigResult.Annotations,
	}

	// If there's a certificate, it's keyless signing.
	if sigResult.HasCertificate {
		keylessInfo, err := extractKeylessSignerFromBundle(sigResult.Bundle)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrExtractKeylessSigner, err)
		}

		result.Keyless = keylessInfo
		result.IsKeyBased = false
	}

	return result, nil
}

// extractKeylessSignerFromBundle extracts keyless signer information directly from the bundle's certificate
// without performing full verification.
func extractKeylessSignerFromBundle(b *bundle.Bundle) (*types.KeylessSignerInfo, error) {
	// Get verification content which provides access to the certificate.
	verificationContent, err := b.VerificationContent()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetVerificationContent, err)
	}

	cert := verificationContent.Certificate()
	if cert == nil {
		return nil, ErrNoCertificateInBundle
	}

	// Extract subject from certificate extensions (Fulcio SAN).
	subject := extractSubjectFromCert(cert)

	// Extract issuer from certificate extensions (Fulcio OIDC issuer).
	issuer := extractIssuerFromCert(cert)

	return &types.KeylessSignerInfo{
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
