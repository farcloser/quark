package sigstore

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/farcloser/quark/internal/a_deprecated/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"

	"github.com/farcloser/quark/dev/version"
	"github.com/farcloser/quark/internal/reference"
	"github.com/farcloser/quark/sdk/attest"
)

const (
	// openVEXNamespace is the predicate type for OpenVEX attestations.
	openVEXNamespace = "https://openvex.dev/ns"
	// dssePayloadType is the media type for DSSE envelopes.
	dssePayloadType = "application/vnd.dsse.envelope.v1+json"
	// inTotoPayloadType is the DSSE payload type for in-toto statements.
	inTotoPayloadType = "application/vnd.in-toto+json"
	// statementInTotoV01 is the in-toto statement type version 0.1.
	statementInTotoV01 = "https://in-toto.io/Statement/v0.1"
	// logKeyIndex is the log key for attestation index.
	logKeyIndex = "index"
)

// inTotoStatement represents an in-toto attestation statement.
// See: https://github.com/in-toto/attestation/blob/main/spec/v0.1.0/statement.md
//
//nolint:tagliatelle // JSON field names are defined by in-toto spec.
type inTotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []inTotoSubject `json:"subject"`
	Predicate     any             `json:"predicate"`
}

// inTotoSubject identifies a software artifact.
type inTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// AttestOptions contains options for attesting an image with VEX.
type AttestOptions struct {
	// ImageRef is the parsed image reference.
	ImageRef reference.ImageReference

	// Digest is the image digest to attest (sha256:...).
	Digest string

	// OIDCIssuer is the OIDC token issuer URL for keyless signing.
	OIDCIssuer string

	// OIDCToken is the JWT token for keyless signing.
	OIDCToken string

	// PrivateKey is the PEM-encoded private key for key-based signing.
	PrivateKey []byte

	// KeyPassword is the optional password for encrypted private keys.
	KeyPassword string

	// RegistryClient is the registry client for pushing the attestation.
	RegistryClient *registry.Client

	// PublishToTransparencyLog uploads the attestation to Rekor.
	// When false, verification requires --insecure-ignore-tlog.
	PublishToTransparencyLog bool

	// Files are local VEX files to attach (OpenVEX, CSAF, or CycloneDX format).
	Files []string

	// Statements are inline VEX statements for suppressing vulnerabilities.
	Statements []*attest.Statement

	// Log is the logger for attestation output.
	Log *slog.Logger
}

// openVEXDocument represents an OpenVEX document structure.
type openVEXDocument struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Statements []openVEXStatement `json:"statements"`
}

// openVEXStatement represents a single statement in an OpenVEX document.
type openVEXStatement struct {
	Vulnerability openVEXVulnerability `json:"vulnerability"`
	Products      []openVEXProduct     `json:"products"`
	Status        string               `json:"status"`
	Justification string               `json:"justification,omitempty"`
}

// openVEXVulnerability identifies the vulnerability.
type openVEXVulnerability struct {
	Name string `json:"name"`
}

// openVEXProduct identifies the affected product.
type openVEXProduct struct {
	ID string `json:"@id"`
}

// Attest attaches VEX attestations to a container image.
// Supports both keyless (OIDC/Fulcio) and key-based signing.
func Attest(ctx context.Context, opts *AttestOptions) error {
	// Validate options.
	hasOIDC := opts.OIDCIssuer != "" && opts.OIDCToken != ""
	hasKey := len(opts.PrivateKey) > 0

	if !hasOIDC && !hasKey {
		return ErrNoSigningMethod
	}

	if opts.RegistryClient == nil {
		return fmt.Errorf("%w: registry client is required", ErrAttestFailed)
	}

	// Collect VEX predicates to attest
	var vexPredicates [][]byte

	// Read provided VEX files
	for _, filePath := range opts.Files {
		predicate, err := readVEXFile(filePath)
		if err != nil {
			return fmt.Errorf("%w: failed to read VEX file %s: %w", ErrAttestFailed, filePath, err)
		}

		vexPredicates = append(vexPredicates, predicate)
	}

	// Generate VEX predicate from inline statements if provided
	if len(opts.Statements) > 0 {
		predicate, err := generateVEXPredicate(opts.Statements)
		if err != nil {
			return fmt.Errorf("%w: failed to generate VEX predicate: %w", ErrAttestFailed, err)
		}

		vexPredicates = append(vexPredicates, predicate)
	}

	if len(vexPredicates) == 0 {
		return fmt.Errorf("%w: %w", ErrAttestFailed, attest.ErrNoStatements)
	}

	opts.Log.DebugContext(ctx, "attesting image with VEX",
		"image", opts.ImageRef.String(),
		"digest", opts.Digest,
		"keyless", hasOIDC,
		"tlog", opts.PublishToTransparencyLog,
		"predicates", len(vexPredicates))

	// Build image reference with digest for subject
	imageWithDigest := fmt.Sprintf("%s@%s", opts.ImageRef.Name(), opts.Digest)

	// Attest each VEX predicate
	for i, predicate := range vexPredicates {
		if err := attestPredicate(ctx, imageWithDigest, predicate, opts, i); err != nil {
			return err
		}
	}

	opts.Log.InfoContext(ctx, "image attested successfully",
		"image", opts.ImageRef.String(),
		"digest", opts.Digest,
		"attestations", len(vexPredicates))

	return nil
}

// attestPredicate creates and pushes a single attestation for a VEX predicate.
func attestPredicate(
	ctx context.Context,
	imageWithDigest string,
	predicate []byte,
	opts *AttestOptions,
	index int,
) error {
	// Create in-toto statement with VEX predicate
	statement, err := createInTotoStatement(imageWithDigest, opts.Digest, predicate)
	if err != nil {
		return fmt.Errorf("%w: failed to create in-toto statement: %w", ErrAttestFailed, err)
	}

	// Marshal statement to JSON
	statementJSON, err := json.Marshal(statement)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal statement: %w", ErrAttestFailed, err)
	}

	opts.Log.DebugContext(ctx, "created in-toto statement",
		"index", index,
		"predicateType", openVEXNamespace)

	// Use sigstore-go Bundle API for signing and optional Rekor upload
	bundle, err := createAttestationBundle(ctx, statementJSON, opts)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAttestFailed, err)
	}

	hasOIDC := opts.OIDCIssuer != "" && opts.OIDCToken != ""

	opts.Log.DebugContext(ctx, "created attestation bundle",
		logKeyIndex, index,
		"keyless", hasOIDC,
		"hasTlog", bundle.GetVerificationMaterial().GetTlogEntries() != nil)

	// Push attestation to registry
	if err := pushAttestation(ctx, opts, bundle); err != nil {
		return fmt.Errorf("%w: %w", ErrPushAttestation, err)
	}

	opts.Log.DebugContext(ctx, "attestation pushed to registry",
		logKeyIndex, index)

	return nil
}

// createAttestationBundle creates a signed attestation bundle using sigstore-go.
func createAttestationBundle(
	ctx context.Context,
	statementJSON []byte,
	opts *AttestOptions,
) (*protobundle.Bundle, error) {
	// Create DSSE content for signing
	content := &sign.DSSEData{
		Data:        statementJSON,
		PayloadType: inTotoPayloadType,
	}

	// Build bundle options
	bundleOpts := sign.BundleOptions{
		Context: ctx,
	}

	// Create keypair based on signing method
	keypair, err := createKeypair(ctx, opts, &bundleOpts)
	if err != nil {
		return nil, err
	}

	// Add Rekor transparency log if requested
	if opts.PublishToTransparencyLog {
		bundleOpts.TransparencyLogs = []sign.Transparency{sign.NewRekor(&sign.RekorOptions{
			BaseURL: "https://rekor.sigstore.dev",
		})}
	}

	// Create the bundle (handles signing, DSSE envelope, and Rekor upload)
	bundle, err := sign.Bundle(content, keypair, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create bundle: %w", err)
	}

	return bundle, nil
}

// createKeypair creates a keypair based on signing method (keyless or key-based).
func createKeypair(_ context.Context, opts *AttestOptions, bundleOpts *sign.BundleOptions) (sign.Keypair, error) {
	hasOIDC := opts.OIDCIssuer != "" && opts.OIDCToken != ""

	if hasOIDC {
		// Create ephemeral keypair for keyless signing
		keypair, err := sign.NewEphemeralKeypair(nil)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCreateEphemeralKeypair, err)
		}

		// Add Fulcio certificate provider
		bundleOpts.CertificateProvider = sign.NewFulcio(nil)
		bundleOpts.CertificateProviderOptions = &sign.CertificateProviderOptions{
			IDToken: opts.OIDCToken,
		}

		return keypair, nil
	}

	// Create keypair from private key
	keypair, err := newStaticKeypair(opts.PrivateKey, opts.KeyPassword)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPrivateKey, err)
	}

	return keypair, nil
}

// pushAttestation pushes the attestation to the registry as a cosign-compatible OCI artifact.
func pushAttestation(
	ctx context.Context,
	opts *AttestOptions,
	bundle *protobundle.Bundle,
) error {
	// Build the attestation tag: sha256-<hex>.att
	// Extract hex from digest (remove "sha256:" prefix).
	const sha256PrefixLen = 7 // len("sha256:")

	digestHex := opts.Digest
	if len(digestHex) > sha256PrefixLen && digestHex[:sha256PrefixLen] == "sha256:" {
		digestHex = digestHex[sha256PrefixLen:]
	}

	// Construct the attestation tag reference string and parse it.
	attTagStr := fmt.Sprintf("%s:sha256-%s.att",
		opts.ImageRef.Name(),
		digestHex)

	attRef, err := reference.Parse(attTagStr)
	if err != nil {
		return fmt.Errorf("failed to parse attestation tag: %w", err)
	}

	// Extract DSSE envelope from bundle
	dsseEnvelope := bundle.GetDsseEnvelope()
	if dsseEnvelope == nil {
		return ErrNoDSSEEnvelope
	}

	// Marshal envelope to JSON
	envelopeJSON, err := json.Marshal(dsseEnvelope)
	if err != nil {
		return fmt.Errorf("failed to marshal DSSE envelope: %w", err)
	}

	// Create annotations for the attestation layer
	annotations := map[string]string{
		"dev.sigstore.cosign/predicatetype": openVEXNamespace,
	}

	// Add certificate if present (keyless signing)
	if cert := bundle.GetVerificationMaterial().GetCertificate(); cert != nil {
		certPEM := string(cert.GetRawBytes())
		annotations["dev.cosignproject.cosign/certificate"] = certPEM
		annotations["dev.sigstore.cosign/certificate"] = certPEM
	}

	// Add transparency log bundle if present
	if tlogEntries := bundle.GetVerificationMaterial().GetTlogEntries(); len(tlogEntries) > 0 {
		bundleJSON, err := createBundleJSONFromProto(tlogEntries[0])
		if err == nil {
			annotations["dev.sigstore.cosign/bundle"] = bundleJSON
		}
	}

	// Create a static layer with the DSSE envelope
	layer := static.NewLayer(envelopeJSON, types.MediaType(dssePayloadType))

	// Create an empty image and add the layer
	img := empty.Image

	img, err = mutate.Append(img, mutate.Addendum{
		Layer:       layer,
		Annotations: annotations,
	})
	if err != nil {
		return fmt.Errorf("failed to create attestation image: %w", err)
	}

	// Push the attestation image using the registry client
	if err := opts.RegistryClient.WriteImage(ctx, *attRef, img); err != nil {
		return fmt.Errorf("failed to push attestation: %w", err)
	}

	opts.Log.DebugContext(ctx, "attestation pushed to registry",
		"tag", attTagStr)

	return nil
}

// createInTotoStatement creates an in-toto statement with a VEX predicate.
func createInTotoStatement(imageRef, digest string, predicate []byte) (*inTotoStatement, error) {
	// Parse predicate JSON to interface for embedding
	var predicateObj any
	if err := json.Unmarshal(predicate, &predicateObj); err != nil {
		return nil, fmt.Errorf("invalid predicate JSON: %w", err)
	}

	// Extract hash algorithm and value from digest
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: %s", ErrInvalidDigestFormat, digest)
	}

	hashAlgo, hashValue := parts[0], parts[1]

	return &inTotoStatement{
		Type:          statementInTotoV01,
		PredicateType: openVEXNamespace,
		Subject: []inTotoSubject{
			{
				Name: imageRef,
				Digest: map[string]string{
					hashAlgo: hashValue,
				},
			},
		},
		Predicate: predicateObj,
	}, nil
}

// readVEXFile reads a VEX file from disk and returns its contents.
func readVEXFile(filePath string) ([]byte, error) {
	content, err := readFile(filePath)
	if err != nil {
		return nil, err
	}

	// Validate it's valid JSON
	var obj any
	if err := json.Unmarshal(content, &obj); err != nil {
		return nil, fmt.Errorf("invalid JSON in VEX file: %w", err)
	}

	return content, nil
}

// generateVEXPredicate creates an OpenVEX document from inline statements.
func generateVEXPredicate(statements []*attest.Statement) ([]byte, error) {
	if len(statements) == 0 {
		return nil, nil
	}

	doc := openVEXDocument{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        fmt.Sprintf("urn:uuid:quark-vex-%d", time.Now().UnixNano()),
		Author:    version.Name,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   1,
	}

	for _, stmt := range statements {
		doc.Statements = append(doc.Statements, openVEXStatement{
			Vulnerability: openVEXVulnerability{Name: stmt.Vulnerability},
			Products:      []openVEXProduct{{ID: stmt.Product}},
			Status:        "not_affected",
			Justification: stmt.Justification,
		})
	}

	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMarshalVEX, err)
	}

	return data, nil
}

// readFile reads a file from disk.
func readFile(filePath string) ([]byte, error) {
	//nolint:gosec // File path comes from user configuration
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	return content, nil
}
