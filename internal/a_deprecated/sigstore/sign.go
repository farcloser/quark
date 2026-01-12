package sigstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"maps"

	"github.com/farcloser/quark/dev/trust"
	"github.com/farcloser/quark/internal/a_deprecated/registry"
	"github.com/farcloser/quark/internal/reference"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/sign"
)

// tlogEntry contains transparency log entry information for signature annotations.
type tlogEntry struct {
	LogIndex   int64
	LogID      string
	IntegTime  int64
	Body       string // Base64-encoded log entry body
	SignedData string // SET (Signed Entry Timestamp)
}

// SignOptions contains options for signing an image.
type SignOptions struct {
	// ImageRef is the parsed image reference.
	ImageRef reference.ImageReference

	// Digest is the image digest to sign (sha256:...).
	Digest string

	// OIDCIssuer is the OIDC token issuer URL for keyless signing.
	OIDCIssuer string

	// OIDCToken is the JWT token for keyless signing.
	OIDCToken string

	// PrivateKey is the PEM-encoded private key for key-based signing.
	PrivateKey []byte

	// KeyPassword is the optional password for encrypted private keys.
	KeyPassword string

	// RegistryClient is the registry client for pushing the signature.
	RegistryClient *registry.Client

	// PublishToTransparencyLog uploads the signature to Rekor.
	// When false, verification requires --insecure-ignore-tlog.
	PublishToTransparencyLog bool

	// Annotations are custom key-value pairs to attach to the signature.
	Annotations map[string]string

	// Log is the logger for signing output.
	Log *slog.Logger
}

// Sign signs a container image and pushes the signature to the registry.
// Supports both keyless (OIDC/Fulcio) and key-based signing.
func Sign(ctx context.Context, opts *SignOptions) error {
	// Validate options.
	hasOIDC := opts.OIDCIssuer != "" && opts.OIDCToken != ""
	hasKey := len(opts.PrivateKey) > 0

	if !hasOIDC && !hasKey {
		return ErrNoSigningMethod
	}

	opts.Log.DebugContext(ctx, "signing image", //revive:disable-line:add-constant
		"image", opts.ImageRef.String(),
		"digest", opts.Digest,
		"keyless", hasOIDC,
		"tlog", opts.PublishToTransparencyLog)

	// Create the simple signing payload.
	payload := createSimpleSigningPayload(opts.ImageRef.String(), opts.Digest)

	// Sign the payload.
	var (
		signature   []byte
		certificate []byte
		publicKey   []byte
		err         error
	)

	if hasOIDC {
		signature, certificate, err = signKeyless(ctx, payload, opts)
	} else {
		signature, publicKey, err = signWithKey(payload, opts)
	}

	if err != nil {
		return fmt.Errorf("%w: %w", ErrSigningFailed, err)
	}

	// Upload to transparency log if requested.
	var entry *tlogEntry

	if opts.PublishToTransparencyLog {
		// Use certificate for keyless, public key for key-based signing.
		pemBytes := certificate
		if len(pemBytes) == 0 {
			pemBytes = publicKey
		}

		entry, err = uploadToRekor(ctx, signature, payload, pemBytes)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrRekorUploadFailed, err)
		}

		opts.Log.DebugContext(ctx, "uploaded to transparency log", //revive:disable-line:add-constant
			"logIndex", entry.LogIndex,
			"logID", entry.LogID)
	}

	// Push signature to registry.
	if err := pushSignature(ctx, opts, payload, signature, certificate, entry, opts.Annotations); err != nil {
		return fmt.Errorf("%w: %w", ErrPushSignature, err)
	}

	opts.Log.InfoContext(ctx, "image signed successfully",
		"image", opts.ImageRef.String(), //revive:disable-line:add-constant
		"digest", opts.Digest) //revive:disable-line:add-constant

	return nil
}

// simpleSigningPayload is the cosign simple signing payload format.
type simpleSigningPayload struct {
	Critical criticalData `json:"critical"`
}

type criticalData struct {
	Image    imageData `json:"image"`
	Type     string    `json:"type"`
	Identity identity  `json:"identity"`
}

//nolint:tagliatelle // JSON field names are defined by cosign spec.
type imageData struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}

//nolint:tagliatelle // JSON field names are defined by cosign spec.
type identity struct {
	DockerReference string `json:"docker-reference"`
}

// createSimpleSigningPayload creates the cosign simple signing payload.
func createSimpleSigningPayload(imageRef, digest string) []byte {
	payload := simpleSigningPayload{
		Critical: criticalData{
			Image: imageData{
				DockerManifestDigest: digest,
			},
			Type: "cosign container image signature",
			Identity: identity{
				DockerReference: imageRef,
			},
		},
	}

	data, _ := json.Marshal(payload)

	return data
}

// signKeyless signs using Fulcio keyless signing.
// Returns (signature, certificate, error).
func signKeyless(
	ctx context.Context,
	payload []byte,
	opts *SignOptions,
) (signature, certificate []byte, err error) {
	// Create ephemeral keypair.
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrCreateEphemeralKeypair, err)
	}

	// Get certificate from Fulcio.
	fulcio := sign.NewFulcio(nil) // Uses default public Fulcio instance

	certOpts := &sign.CertificateProviderOptions{
		IDToken: opts.OIDCToken,
	}

	certBytes, err := fulcio.GetCertificate(ctx, keypair, certOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrFulcioCertificateFailed, err)
	}

	// Sign the payload.
	signature, _, err = keypair.SignData(ctx, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrSignPayload, err)
	}

	// Convert certificate to PEM.
	certificate = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return signature, certificate, nil
}

// signWithKey signs using a private key.
// Returns (signature, publicKeyPEM, error).
func signWithKey(payload []byte, opts *SignOptions) (signature, publicKeyPEM []byte, err error) {
	// Parse the private key.
	block, _ := pem.Decode(opts.PrivateKey)
	if block == nil {
		return nil, nil, fmt.Errorf("%w: failed to decode PEM block", ErrInvalidPrivateKey)
	}

	var privateKey crypto.Signer

	// Try parsing as PKCS8 first, then EC.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool

		privateKey, ok = key.(crypto.Signer)

		if !ok {
			return nil, nil, fmt.Errorf("%w: key does not implement crypto.Signer", ErrInvalidPrivateKey)
		}
	} else if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		privateKey = key
	} else {
		return nil, nil, fmt.Errorf("%w: unsupported key format", ErrInvalidPrivateKey)
	}

	// Sign the payload.
	hash := crypto.SHA256
	hasher := hash.New()
	_, _ = hasher.Write(payload)
	digest := hasher.Sum(nil)

	signature, err = privateKey.Sign(nil, digest, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrSign, err)
	}

	// Extract and encode the public key for Rekor upload.
	if ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey); ok {
		publicKeyPEM, err = trust.PublicKeyToPEM(&ecdsaKey.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrEncodePublicKey, err)
		}
	}

	return signature, publicKeyPEM, nil
}

// pushSignature pushes the signature to the registry as a cosign-compatible OCI artifact.
func pushSignature(
	ctx context.Context,
	opts *SignOptions,
	payload, signature, certificate []byte,
	entry *tlogEntry,
	customAnnotations map[string]string,
) error {
	// Build the signature tag: sha256-<hex>.sig
	// Extract hex from digest (remove "sha256:" prefix).
	const sha256PrefixLen = 7 // len("sha256:")

	digestHex := opts.Digest
	if len(digestHex) > sha256PrefixLen && digestHex[:sha256PrefixLen] == "sha256:" {
		digestHex = digestHex[sha256PrefixLen:]
	}

	// Construct the signature tag reference string and parse it.
	sigTagStr := fmt.Sprintf("%s:sha256-%s.sig",
		opts.ImageRef.Name(),
		digestHex)

	sigRef, err := reference.Parse(sigTagStr)
	if err != nil {
		return fmt.Errorf("%w: failed to parse signature tag: %w", ErrPushSignature, err)
	}

	// Create the signature layer with cosign format.
	// Store signature with both annotation prefixes for compatibility:
	// - "dev.cosignproject.cosign/" is the original prefix (used by cosign verify)
	// - "dev.sigstore.cosign/" is the newer prefix after sigstore rebranding
	encodedSig := base64.StdEncoding.EncodeToString(signature)
	annotations := map[string]string{
		"dev.cosignproject.cosign/signature": encodedSig,
		"dev.sigstore.cosign/signature":      encodedSig,
	}

	if len(certificate) > 0 {
		certPEM := string(certificate)
		annotations["dev.cosignproject.cosign/certificate"] = certPEM
		annotations["dev.sigstore.cosign/certificate"] = certPEM
	}

	// Add transparency log annotations if entry was uploaded.
	if entry != nil {
		annotations["dev.sigstore.cosign/bundle"] = createBundleJSON(entry)
	}

	// Add custom annotations.
	maps.Copy(annotations, customAnnotations)

	// Create a static layer with the payload.
	layer := static.NewLayer(payload, types.MediaType("application/vnd.dev.cosign.simplesigning.v1+json"))

	// Create an empty image and add the layer.
	img := empty.Image

	img, err = mutate.Append(img, mutate.Addendum{
		Layer:       layer,
		Annotations: annotations,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCreateSignatureImage, err)
	}

	// Push the signature image using the registry client.
	if err := opts.RegistryClient.WriteImage(ctx, *sigRef, img); err != nil {
		return fmt.Errorf("%w: %w", ErrPushSignature, err)
	}

	opts.Log.DebugContext(ctx, "signature pushed to registry", //revive:disable-line:add-constant
		"tag", sigTagStr)

	return nil
}

// uploadToRekor uploads a signature to the Rekor transparency log.
// Returns the log entry information needed for signature annotations.
func uploadToRekor(
	ctx context.Context,
	signature, payload, pemBytes []byte,
) (*tlogEntry, error) {
	// Create Rekor client with HTTPS (default uses HTTP).
	cfg := client.DefaultTransportConfig().WithSchemes([]string{"https"})
	rekorClient := client.NewHTTPClientWithConfig(nil, cfg)

	// Create hashedrekord entry.
	// The hashedrekord type allows uploading a hash of the payload instead of the full payload.
	re := newHashedRekordEntry(signature, payload, pemBytes)

	params := entries.NewCreateLogEntryParamsWithContext(ctx)
	params.SetProposedEntry(re)

	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCreateLogEntry, err)
	}

	// Extract entry information from response.
	// The response payload is a map with UUID as key; we only need the first entry.
	for _, entry := range resp.Payload {
		// Body is already base64-encoded in the response.
		body, ok := entry.Body.(string)
		if !ok {
			return nil, ErrRekorUnexpectedBody
		}

		return &tlogEntry{
			LogIndex:   *entry.LogIndex,
			LogID:      *entry.LogID,
			IntegTime:  *entry.IntegratedTime,
			Body:       body,
			SignedData: entry.Verification.SignedEntryTimestamp.String(),
		}, nil
	}

	return nil, ErrRekorEmptyResponse
}

// newHashedRekordEntry creates a hashedrekord entry for Rekor.
func newHashedRekordEntry(signature, payload, pemBytes []byte) models.ProposedEntry {
	// Hash the payload.
	hashAlgo := crypto.SHA256
	hasher := hashAlgo.New()
	_, _ = hasher.Write(payload)
	payloadHash := hasher.Sum(nil)

	apiVersion := "0.0.1"
	algorithm := "sha256"
	hashValue := hex.EncodeToString(payloadHash)

	return &models.Hashedrekord{
		APIVersion: &apiVersion,
		Spec: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: &algorithm,
					Value:     &hashValue,
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: signature,
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: pemBytes,
				},
			},
		},
	}
}

// bundlePayload represents the cosign bundle format for transparency log proof.
//
//nolint:tagliatelle // JSON field names are defined by cosign bundle spec.
type bundlePayload struct {
	SignedEntryTimestamp string         `json:"SignedEntryTimestamp"`
	Payload              bundleLogEntry `json:"Payload"`
}

//nolint:tagliatelle // JSON field names are defined by cosign bundle spec.
type bundleLogEntry struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogIndex       int64  `json:"logIndex"`
	LogID          string `json:"logID"`
}

// createBundleJSON creates the JSON bundle annotation for cosign verification.
func createBundleJSON(entry *tlogEntry) string {
	bundle := bundlePayload{
		SignedEntryTimestamp: entry.SignedData,
		Payload: bundleLogEntry{
			Body:           entry.Body,
			IntegratedTime: entry.IntegTime,
			LogIndex:       entry.LogIndex,
			LogID:          entry.LogID,
		},
	}

	data, _ := json.Marshal(bundle)

	return string(data)
}

// createBundleJSONFromProto creates the JSON bundle annotation from a protobuf tlog entry.
func createBundleJSONFromProto(entry *protorekor.TransparencyLogEntry) (string, error) {
	if entry == nil {
		return "", ErrNilTlogEntry
	}

	// Get the signed entry timestamp from inclusion promise
	var signedTimestamp string
	if entry.GetInclusionPromise() != nil {
		signedTimestamp = base64.StdEncoding.EncodeToString(entry.GetInclusionPromise().GetSignedEntryTimestamp())
	}

	// Get log ID
	var logID string
	if entry.GetLogId() != nil {
		logID = hex.EncodeToString(entry.GetLogId().GetKeyId())
	}

	// Get canonicalized body
	body := base64.StdEncoding.EncodeToString(entry.GetCanonicalizedBody())

	bundle := bundlePayload{
		SignedEntryTimestamp: signedTimestamp,
		Payload: bundleLogEntry{
			Body:           body,
			IntegratedTime: entry.GetIntegratedTime(),
			LogIndex:       entry.GetLogIndex(),
			LogID:          logID,
		},
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		return "", fmt.Errorf("failed to marshal bundle: %w", err)
	}

	return string(data), nil
}

// staticKeypair implements sign.Keypair for key-based signing.
type staticKeypair struct {
	privateKey crypto.Signer
	publicKey  crypto.PublicKey
}

// newStaticKeypair creates a Keypair from a PEM-encoded private key.
func newStaticKeypair(privateKeyPEM []byte, _ string) (sign.Keypair, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, ErrDecodePEMBlock
	}

	var privateKey crypto.Signer

	// Try parsing as PKCS8 first, then EC.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool

		privateKey, ok = key.(crypto.Signer)

		if !ok {
			return nil, ErrKeyNotSigner
		}
	} else if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		privateKey = key
	} else {
		return nil, ErrUnsupportedKeyFormat
	}

	return &staticKeypair{
		privateKey: privateKey,
		publicKey:  privateKey.Public(),
	}, nil
}

func (*staticKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_SHA2_256
}

func (*staticKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
}

func (*staticKeypair) GetHint() []byte {
	return nil
}

func (*staticKeypair) GetKeyAlgorithm() string {
	return "ecdsa"
}

func (kp *staticKeypair) GetPublicKey() crypto.PublicKey {
	return kp.publicKey
}

func (kp *staticKeypair) GetPublicKeyPem() (string, error) {
	pemBytes, err := trust.PublicKeyToPEM(kp.publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	return string(pemBytes), nil
}

func (kp *staticKeypair) SignData(_ context.Context, data []byte) (signature, digest []byte, err error) {
	hash := crypto.SHA256
	hasher := hash.New()
	_, _ = hasher.Write(data)
	digestBytes := hasher.Sum(nil)

	signature, err = kp.privateKey.Sign(nil, digestBytes, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrSign, err)
	}

	return signature, nil, nil
}
