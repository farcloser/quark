package cosign

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	v1 "github.com/in-toto/attestation/go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore/pkg/signature/payload"

	"github.com/farcloser/quark/internal/types"
)

// Convert transforms a legacy cosign simple signing payload and its annotations
// into a sigstore bundle (as JSON bytes) that can be verified using sigstore-go.
// Returns the bundle bytes, the bundle media type, and any error.
func Convert(pld []byte, annotations map[string]string) ([]byte, types.MediaType, error) {
	// Validate the payload is a valid simple signing format.
	simple := &payload.SimpleContainerImage{}
	if err := json.Unmarshal(pld, simple); err != nil {
		return nil, "", fmt.Errorf("invalid simple signing payload: %w", err)
	}

	// Keyless signatures have a certificate annotation; key-based do not.
	_, isKeyless := annotations[annotationCertificate]

	return buildBundle(pld, annotations, isKeyless)
}

// ParseSimpleSigning parses a legacy cosign simple signing payload and returns
// an in-toto Statement with the image digest as subject. This is used to extract
// subject information from MessageSignature bundles which don't contain statements.
func ParseSimpleSigning(pld []byte) (*v1.Statement, error) {
	simple := &payload.SimpleContainerImage{}
	if err := json.Unmarshal(pld, simple); err != nil {
		return nil, fmt.Errorf("invalid simple signing payload: %w", err)
	}

	// Extract image digest from the simple signing payload.
	// Format is "sha256:abc123..." or just the algorithm:hash.
	imageDigest := simple.Critical.Image.DockerManifestDigest

	// Parse the digest into algorithm and hash.
	algorithm, hash, found := strings.Cut(imageDigest, ":")
	if !found {
		return nil, fmt.Errorf("invalid digest format: %s", imageDigest)
	}

	// Create an in-toto statement with the image digest as subject.
	return &v1.Statement{
		Type:          statementTypeInToto,
		PredicateType: predicateTypeSignature,
		Subject: []*v1.ResourceDescriptor{
			{
				Digest: map[string]string{
					algorithm: hash,
				},
			},
		},
	}, nil
}

// ConvertAttestation transforms a legacy cosign DSSE envelope and its annotations
// into a sigstore bundle (as JSON bytes) that can be verified using sigstore-go.
// Legacy attestations are raw DSSE envelopes; modern bundles wrap them with verification material.
func ConvertAttestation(envelope []byte, annotations map[string]string) ([]byte, types.MediaType, error) {
	// Parse the DSSE envelope.
	dsseEnvelope, err := parseDSSEEnvelope(envelope)
	if err != nil {
		return nil, "", err
	}

	// Keyless attestations have a certificate annotation; key-based do not.
	_, isKeyless := annotations[annotationCertificate]

	return buildAttestationBundle(dsseEnvelope, annotations, isKeyless)
}

// parseDSSEEnvelope parses a JSON DSSE envelope into protobuf format.
func parseDSSEEnvelope(data []byte) (*protodsse.Envelope, error) {
	// Parse JSON structure.
	var jsonEnv struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			KeyID string `json:"keyid,omitempty"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}

	if err := json.Unmarshal(data, &jsonEnv); err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedParsingDSSEEnvelope, err)
	}

	// Decode base64 payload.
	payload, err := base64.StdEncoding.DecodeString(jsonEnv.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %w", errFailedParsingDSSEEnvelope, err)
	}

	// Build protobuf signatures.
	var sigs []*protodsse.Signature

	for _, s := range jsonEnv.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			return nil, fmt.Errorf("%w: decode signature: %w", errFailedParsingDSSEEnvelope, err)
		}

		sigs = append(sigs, &protodsse.Signature{
			Keyid: s.KeyID,
			Sig:   sig,
		})
	}

	if len(sigs) == 0 {
		return nil, fmt.Errorf("%w: no signatures", errFailedParsingDSSEEnvelope)
	}

	return &protodsse.Envelope{
		Payload:     payload,
		PayloadType: jsonEnv.PayloadType,
		Signatures:  sigs,
	}, nil
}

// buildAttestationBundle creates a sigstore bundle with DSSE envelope content.
func buildAttestationBundle(
	dsseEnvelope *protodsse.Envelope,
	annotations map[string]string,
	includeCert bool,
) ([]byte, types.MediaType, error) {
	// Build verification material (same as signatures).
	verificationMaterial, err := buildVerificationMaterial(annotations, includeCert)
	if err != nil {
		return nil, "", err
	}

	// Construct the bundle. Failure means we have a serious problem. Panic.
	bundleMediaType, err := bundle.MediaTypeString(bundleVersion)
	if err != nil {
		panic(fmt.Errorf("get bundle media type: %w", err))
	}

	protoBundle := protobundle.Bundle{
		MediaType:            bundleMediaType,
		VerificationMaterial: verificationMaterial,
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: dsseEnvelope,
		},
	}

	b, err := bundle.NewBundle(&protoBundle)
	if err != nil {
		return nil, "", fmt.Errorf("create bundle: %w", err)
	}

	bundleBytes, err := b.MarshalJSON()
	if err != nil {
		return nil, "", fmt.Errorf("marshal bundle: %w", err)
	}

	return bundleBytes, types.MediaType(bundleMediaType), nil
}

func buildBundle(pld []byte, annotations map[string]string, includeCert bool) ([]byte, types.MediaType, error) {
	// Build verification material.
	verificationMaterial, err := buildVerificationMaterial(annotations, includeCert)
	if err != nil {
		return nil, "", err
	}

	// Build message signature with digest of the payload.
	msgSignature, err := buildMessageSignature(pld, annotations)
	if err != nil {
		return nil, "", err
	}

	// Construct the bundle. Failure means we have a serious problem. Panic.
	bundleMediaType, err := bundle.MediaTypeString(bundleVersion)
	if err != nil {
		panic(fmt.Errorf("get bundle media type: %w", err))
	}

	protoBundle := protobundle.Bundle{
		MediaType:            bundleMediaType,
		VerificationMaterial: verificationMaterial,
		Content:              msgSignature,
	}

	b, err := bundle.NewBundle(&protoBundle)
	if err != nil {
		return nil, "", fmt.Errorf("create bundle: %w", err)
	}

	bundleBytes, err := b.MarshalJSON()
	if err != nil {
		return nil, "", fmt.Errorf("marshal bundle: %w", err)
	}

	return bundleBytes, types.MediaType(bundleMediaType), nil
}

func buildMessageSignature(pld []byte, annotations map[string]string) (*protobundle.Bundle_MessageSignature, error) {
	sigB64, hasSig := annotations[annotationSignature]
	if !hasSig {
		return nil, fmt.Errorf("%w: missing signature from annotation", errFailedBuildingSignature)
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedBuildingSignature, err)
	}

	// Compute SHA256 digest of the simple signing payload.
	digest := sha256.Sum256(pld)

	return &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: protocommon.HashAlgorithm_SHA2_256,
				Digest:    digest[:],
			},
			Signature: sig,
		},
	}, nil
}

func buildVerificationMaterial(
	annotations map[string]string,
	includeCert bool,
) (*protobundle.VerificationMaterial, error) {
	// Get transparency log entries.
	tlogEntries, err := extractTlogEntries(annotations)
	if err != nil {
		return nil, err
	}

	// For keyless, include X.509 certificate chain.
	if includeCert {
		certChain, err := extractCertificateChain(annotations)
		if err != nil {
			return nil, err
		}

		return &protobundle.VerificationMaterial{
			Content:     certChain,
			TlogEntries: tlogEntries,
		}, nil
	}

	// For key-based signatures, use publicKey with empty hint.
	// The hint is ignored during verification - the caller provides the actual key.
	return &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_PublicKey{
			PublicKey: &protocommon.PublicKeyIdentifier{
				Hint: "",
			},
		},
		TlogEntries: tlogEntries,
	}, nil
}

func extractCertificateChain(
	annotations map[string]string,
) (*protobundle.VerificationMaterial_X509CertificateChain, error) {
	pemCert, hasCert := annotations[annotationCertificate]
	if !hasCert {
		return nil, fmt.Errorf("%w: missing certificate", errFailedExtractingCertChain)
	}

	var certs []*protocommon.X509Certificate

	pemData := []byte(pemCert)

	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		// Verify it's a valid X.509 certificate.
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("%w: invalid certificate: %w", errFailedExtractingCertChain, err)
		}

		certs = append(certs, &protocommon.X509Certificate{RawBytes: block.Bytes})
		pemData = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: missing PEM", errFailedExtractingCertChain)
	}

	return &protobundle.VerificationMaterial_X509CertificateChain{
		X509CertificateChain: &protocommon.X509CertificateChain{
			Certificates: certs,
		},
	}, nil
}

func extractTlogEntries(annotations map[string]string) ([]*protorekor.TransparencyLogEntry, error) {
	bundleAnnotation, hasBundle := annotations[annotationBundle]
	if !hasBundle {
		// No tlog entries - may be acceptable depending on policy.
		return nil, nil
	}

	var jsonData map[string]any
	if err := json.Unmarshal([]byte(bundleAnnotation), &jsonData); err != nil {
		return nil, fmt.Errorf("%w: unmarshal bundle annotation: %w", errFailedExtractingTLogEntries, err)
	}

	payload, payloadOK := jsonData["Payload"].(map[string]any)
	if !payloadOK {
		return nil, fmt.Errorf("%w: missing Payload", errFailedExtractingTLogEntries)
	}

	logIndex, logIndexOK := payload["logIndex"].(float64)
	if !logIndexOK {
		return nil, fmt.Errorf("%w: missing logIndex", errFailedExtractingTLogEntries)
	}

	logIDHex, logIDOK := payload["logID"].(string)
	if !logIDOK {
		return nil, fmt.Errorf("%w: missing logID", errFailedExtractingTLogEntries)
	}

	logID, err := hex.DecodeString(logIDHex)
	if err != nil {
		return nil, fmt.Errorf("%w: decode logID: %w", errFailedExtractingTLogEntries, err)
	}

	integratedTime, timeOK := payload["integratedTime"].(float64)
	if !timeOK {
		return nil, fmt.Errorf("%w: missing integratedTime", errFailedExtractingTLogEntries)
	}

	setB64, setOK := jsonData["SignedEntryTimestamp"].(string)
	if !setOK {
		return nil, fmt.Errorf("%w: missing SignedEntryTimestamp", errFailedExtractingTLogEntries)
	}

	signedEntryTimestamp, err := base64.StdEncoding.DecodeString(setB64)
	if err != nil {
		return nil, fmt.Errorf("%w: decode signedEntryTimestamp: %w", errFailedExtractingTLogEntries, err)
	}

	bodyB64, bodyOK := payload["body"].(string)
	if !bodyOK {
		return nil, fmt.Errorf("%w: missing body", errFailedExtractingTLogEntries)
	}

	bodyBytes, err := base64.StdEncoding.DecodeString(bodyB64)
	if err != nil {
		return nil, fmt.Errorf("%w: decode body: %w", errFailedExtractingTLogEntries, err)
	}

	// Extract kind version from body.
	var bodyJSON map[string]any
	if err := json.Unmarshal(bodyBytes, &bodyJSON); err != nil {
		return nil, fmt.Errorf("%w: unmarshal body: %w", errFailedExtractingTLogEntries, err)
	}

	apiVersion, _ := bodyJSON["apiVersion"].(string)
	kind, _ := bodyJSON["kind"].(string)

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
