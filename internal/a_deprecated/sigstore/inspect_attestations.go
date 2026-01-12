package sigstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/internal/a_deprecated/registry"
	"github.com/farcloser/quark/internal/types"
	"github.com/google/go-containerregistry/pkg/v1"

	"github.com/farcloser/quark/internal/reference"
)

const (
	// attTagFormat is the format for attestation tags: <name>:<algorithm>-<hash>.att.
	attTagFormat = "%s:%s-%s.att"
	// predicateTypeAnnotation is the annotation key for predicate type.
	predicateTypeAnnotation = "dev.sigstore.cosign/predicatetype"
	// logKeyReason is the log key for error reason.
	logKeyReason = "reason"
)

// InspectAttestationsOptions contains options for inspecting image attestations.
type InspectAttestationsOptions struct {
	// ImageRef is the parsed image reference.
	ImageRef reference.ImageReference

	// Digest is the image digest (sha256:...). Required.
	Digest string

	// RegistryClient is the registry client for fetching attestation artifacts.
	RegistryClient *registry.Client

	// Log is the logger for output.
	Log *slog.Logger
}

// AttestationsResult contains all attestations found for an image.
type AttestationsResult struct {
	// HasAttestations indicates whether any attestations were found.
	HasAttestations bool

	// Digest is the image digest these attestations apply to.
	Digest string

	// Attestations is the list of attestation entries found.
	Attestations []AttestationEntry
}

// AttestationEntry represents a single attestation from the .att artifact.
type AttestationEntry struct {
	// PredicateType is the type of the attestation predicate.
	// e.g., "https://openvex.dev/ns", "https://slsa.dev/provenance/v1"
	PredicateType string

	// Predicate is the raw predicate content (JSON bytes).
	Predicate []byte

	// IsSigned indicates whether this attestation has a signature.
	IsSigned bool

	// Keyless contains identity info if this is a keyless (Fulcio) signature.
	// Nil if the attestation is key-based or unsigned.
	Keyless *types.KeylessSignerInfo

	// IsKeyBased is true if the attestation was signed with a private key (no certificate).
	IsKeyBased bool

	// Annotations are custom key-value pairs attached to the attestation layer.
	// Sigstore-reserved annotations are filtered out.
	Annotations map[string]string
}

// dsseEnvelope represents a DSSE envelope structure for parsing.
// See: https://github.com/secure-systems-lab/dsse/blob/master/envelope.md
type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"` // base64-encoded
	Signatures  []dsseSignature `json:"signatures"`
}

// dsseSignature represents a signature within a DSSE envelope.
type dsseSignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"` // base64-encoded
}

// inTotoStatementPartial is used to extract predicate from in-toto statement.
// We only need the predicate field for inspection.
type inTotoStatementPartial struct {
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// InspectAttestations retrieves attestation information for an image without verification.
// Returns an empty result (not an error) if no attestations are found.
func InspectAttestations(ctx context.Context, opts *InspectAttestationsOptions) (*AttestationsResult, error) {
	opts.Log.DebugContext(ctx, "inspecting image attestations",
		"image", opts.ImageRef.String(),
		"digest", opts.Digest)

	digDigest := types.Digest(opts.Digest)

	// Build attestation tag: sha256-<hex>.att
	attTagStr := fmt.Sprintf(attTagFormat,
		opts.ImageRef.Name(),
		digDigest.Algorithm(),
		digDigest.Hex())

	attRef, err := reference.Parse(attTagStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseAttestationTag, err)
	}

	// Try to fetch the attestation image.
	attImage, err := opts.RegistryClient.GetImageHandle(ctx, *attRef)
	if err != nil {
		// No attestations found - this is not an error condition.
		opts.Log.DebugContext(ctx, "no attestation artifact found",
			"tag", attTagStr,
			logKeyReason, err.Error())

		return &AttestationsResult{
			HasAttestations: false,
			Digest:          opts.Digest,
		}, nil
	}

	// Get manifest to access layer metadata (annotations).
	attManifest, err := attImage.Manifest()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetAttestationManifest, err)
	}

	if len(attManifest.Layers) == 0 {
		return &AttestationsResult{
			HasAttestations: false,
			Digest:          opts.Digest,
		}, nil
	}

	// Get all layers for content extraction.
	layers, err := attImage.Layers()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGetAttestationLayers, err)
	}

	// Process each layer as a potential attestation.
	attestations := make([]AttestationEntry, 0, len(attManifest.Layers))

	for layerIdx, layerDesc := range attManifest.Layers {
		// Check media type - attestations use DSSE envelope format.
		if string(layerDesc.MediaType) != dssePayloadType {
			opts.Log.DebugContext(ctx, "skipping layer with non-DSSE media type",
				"index", layerIdx,
				"mediaType", layerDesc.MediaType)

			continue
		}

		entry, err := extractAttestationFromLayer(ctx, &layerDesc, layers[layerIdx], opts.Log)
		if err != nil {
			opts.Log.DebugContext(ctx, "failed to extract attestation entry",
				"index", layerIdx,
				logKeyReason, err.Error())

			continue
		}

		attestations = append(attestations, *entry)
	}

	return &AttestationsResult{
		HasAttestations: len(attestations) > 0,
		Digest:          opts.Digest,
		Attestations:    attestations,
	}, nil
}

// extractAttestationFromLayer extracts attestation information from a single layer.
func extractAttestationFromLayer(
	ctx context.Context,
	layerDesc *v1.Descriptor,
	layer v1.Layer,
	log *slog.Logger,
) (*AttestationEntry, error) {
	// Read layer content.
	layerReader, err := layer.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadAttestationLayer, err)
	}
	defer layerReader.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(layerReader); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadAttestationContent, err)
	}

	layerContent := buf.Bytes()
	annotations := layerDesc.Annotations

	// Parse DSSE envelope to get payload.
	var envelope dsseEnvelope
	if err := json.Unmarshal(layerContent, &envelope); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseDSSEEnvelope, err)
	}

	// Decode the base64-encoded payload (in-toto statement).
	statementJSON, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecodeAttestationPayload, err)
	}

	// Parse the in-toto statement to extract predicate.
	var statement inTotoStatementPartial
	if err := json.Unmarshal(statementJSON, &statement); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParseInTotoStatement, err)
	}

	// Get predicate type from annotations (preferred) or statement.
	predicateType := annotations[predicateTypeAnnotation]
	if predicateType == "" {
		predicateType = statement.PredicateType
	}

	// Determine signing status.
	hasCert := annotations[certAnnotation] != ""
	hasSignature := len(envelope.Signatures) > 0

	entry := &AttestationEntry{
		PredicateType: predicateType,
		Predicate:     statement.Predicate,
		IsSigned:      hasSignature,
		Keyless:       nil,
		IsKeyBased:    hasSignature && !hasCert,
		Annotations:   extractCustomAnnotations(annotations),
	}

	// Extract keyless signer info if certificate is present.
	if hasCert {
		keylessInfo, err := extractKeylessInfoFromCertPEM(annotations[certAnnotation])
		if err != nil {
			log.DebugContext(ctx, "failed to extract keyless signer info",
				logKeyReason, err.Error())
			// Continue without keyless info - attestation is still valid.
		} else {
			entry.Keyless = keylessInfo
			entry.IsKeyBased = false
		}
	}

	return entry, nil
}

// extractKeylessInfoFromCertPEM extracts keyless signer information from a PEM-encoded certificate.
func extractKeylessInfoFromCertPEM(certPEM string) (*types.KeylessSignerInfo, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, ErrInvalidPEM
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidX509Certificate, err)
	}

	return &types.KeylessSignerInfo{
		Subject: extractSubjectFromCert(cert),
		Issuer:  extractIssuerFromCert(cert),
	}, nil
}
