// Package schemas provides types and parsers for OCI artifact layer formats.
package schemas

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tagvalue"
)

// =============================================================================
// DSSE Envelope (wraps in-toto statements with signatures)
// =============================================================================

// DSSEEnvelope is the Dead Simple Signing Envelope format.
// Used by Cosign/Sigstore to wrap signed in-toto attestations.
// Layer mediaType: application/vnd.dsse.envelope.v1+json
type DSSEEnvelope = dsse.Envelope

// =============================================================================
// In-toto Statement (attestation payload)
// =============================================================================

//// InTotoStatement is an in-toto attestation statement.
//// Used by BuildKit (unsigned) and inside DSSE envelopes (signed).
//// Layer mediaType: application/vnd.in-toto+json
//type InTotoStatement = in_toto.Statement
//
//// =============================================================================
//// Sigstore Bundle (self-contained verification material)
//// =============================================================================
//
//// SigstoreBundle contains signature, certificate, and transparency log proof.
//// Layer mediaType: application/vnd.dev.sigstore.bundle.v0.3+json
//type SigstoreBundle = bundle.Bundle

// =============================================================================
// CycloneDX SBOM
// =============================================================================

// CycloneDXBOM is a CycloneDX Software Bill of Materials.
// Layer mediaType: application/vnd.cyclonedx+json
type CycloneDXBOM = cyclonedx.BOM

// =============================================================================
// SPDX SBOM
// =============================================================================

// SPDXBOM is an SPDX Software Bill of Materials (v2.3).
// Layer mediaType: application/spdx+json
type SPDXBOM = spdx.Document

// =============================================================================
// Cosign Simple Signing (payload structure)
// =============================================================================

// SimpleSigning is the cosign simple signing payload format.
// Layer mediaType: application/vnd.dev.cosign.simplesigning.v1+json
// Note: Cosign doesn't export this type, so we define it here.
type SimpleSigning struct {
	Critical Critical          `json:"critical"`
	Optional map[string]string `json:"optional,omitempty"`
}

// Critical contains the required fields for simple signing.
type Critical struct {
	Identity Identity `json:"identity"`
	Image    Image    `json:"image"`
	Type     string   `json:"type"`
}

// Identity identifies the image reference.
type Identity struct {
	DockerReference string `json:"docker-reference"`
}

// Image identifies the image by digest.
type Image struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}

// =============================================================================
// Parsers
// =============================================================================

// ParseDSSEEnvelope parses a DSSE envelope from JSON bytes.
func ParseDSSEEnvelope(data []byte) (*DSSEEnvelope, error) {
	var envelope DSSEEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("parse DSSE envelope: %w", err)
	}

	return &envelope, nil
}

//// ParseInTotoStatement parses an in-toto statement from JSON bytes.
//func ParseInTotoStatement(data []byte) (*InTotoStatement, error) {
//	var statement InTotoStatement
//	if err := json.Unmarshal(data, &statement); err != nil {
//		return nil, fmt.Errorf("parse in-toto statement: %w", err)
//	}
//
//	return &statement, nil
//}
//
//// ParseSigstoreBundle parses a Sigstore bundle from JSON bytes.
//func ParseSigstoreBundle(data []byte) (*SigstoreBundle, error) {
//	var b SigstoreBundle
//	if err := b.UnmarshalJSON(data); err != nil {
//		return nil, fmt.Errorf("parse sigstore bundle: %w", err)
//	}
//
//	return &b, nil
//}

// ParseSimpleSigning parses a cosign simple signing payload from JSON bytes.
func ParseSimpleSigning(data []byte) (*SimpleSigning, error) {
	var ss SimpleSigning
	if err := json.Unmarshal(data, &ss); err != nil {
		return nil, fmt.Errorf("parse simple signing: %w", err)
	}

	return &ss, nil
}

// ParseCycloneDXJSON parses a CycloneDX SBOM from JSON bytes.
func ParseCycloneDXJSON(data []byte) (*CycloneDXBOM, error) {
	var bom CycloneDXBOM

	decoder := cyclonedx.NewBOMDecoder(bytes.NewReader(data), cyclonedx.BOMFileFormatJSON)
	if err := decoder.Decode(&bom); err != nil {
		return nil, fmt.Errorf("parse cyclonedx json: %w", err)
	}

	return &bom, nil
}

// ParseCycloneDXXML parses a CycloneDX SBOM from XML bytes.
func ParseCycloneDXXML(data []byte) (*CycloneDXBOM, error) {
	var bom CycloneDXBOM

	decoder := cyclonedx.NewBOMDecoder(bytes.NewReader(data), cyclonedx.BOMFileFormatXML)
	if err := decoder.Decode(&bom); err != nil {
		return nil, fmt.Errorf("parse cyclonedx xml: %w", err)
	}

	return &bom, nil
}

// ParseSPDXJSON parses an SPDX SBOM from JSON bytes.
func ParseSPDXJSON(data []byte) (*SPDXBOM, error) {
	var doc SPDXBOM
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse spdx json: %w", err)
	}

	return &doc, nil
}

// ParseSPDXTagValue parses an SPDX SBOM from tag-value (text) format.
func ParseSPDXTagValue(data []byte) (*SPDXBOM, error) {
	doc, err := tagvalue.Read(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse spdx tag-value: %w", err)
	}

	return doc, nil
}

// ParseInTotoBundle parses an in-toto bundle (JSON Lines of DSSE envelopes).
func ParseInTotoBundle(data []byte) ([]*DSSEEnvelope, error) {
	var envelopes []*DSSEEnvelope

	lines := bytes.Split(data, []byte("\n"))
	for i, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		env, err := ParseDSSEEnvelope(line)
		if err != nil {
			return nil, fmt.Errorf("parse in-toto bundle line %d: %w", i+1, err)
		}

		envelopes = append(envelopes, env)
	}

	return envelopes, nil
}

// =============================================================================
// Serializers
// =============================================================================

// SerializeDSSEEnvelope serializes a DSSE envelope to JSON bytes.
func SerializeDSSEEnvelope(envelope *DSSEEnvelope) ([]byte, error) {
	data, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("serialize DSSE envelope: %w", err)
	}

	return data, nil
}

//// SerializeInTotoStatement serializes an in-toto statement to JSON bytes.
//func SerializeInTotoStatement(statement *InTotoStatement) ([]byte, error) {
//	data, err := json.Marshal(statement)
//	if err != nil {
//		return nil, fmt.Errorf("serialize in-toto statement: %w", err)
//	}
//
//	return data, nil
//}
//
//// SerializeSigstoreBundle serializes a Sigstore bundle to JSON bytes.
//func SerializeSigstoreBundle(b *SigstoreBundle) ([]byte, error) {
//	data, err := b.MarshalJSON()
//	if err != nil {
//		return nil, fmt.Errorf("serialize sigstore bundle: %w", err)
//	}
//
//	return data, nil
//}

// SerializeSimpleSigning serializes a cosign simple signing payload to JSON bytes.
func SerializeSimpleSigning(ss *SimpleSigning) ([]byte, error) {
	data, err := json.Marshal(ss)
	if err != nil {
		return nil, fmt.Errorf("serialize simple signing: %w", err)
	}

	return data, nil
}

// SerializeCycloneDXJSON serializes a CycloneDX SBOM to JSON bytes.
func SerializeCycloneDXJSON(bom *CycloneDXBOM) ([]byte, error) {
	var buf bytes.Buffer

	encoder := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON)
	if err := encoder.Encode(bom); err != nil {
		return nil, fmt.Errorf("serialize cyclonedx json: %w", err)
	}

	return buf.Bytes(), nil
}

// SerializeCycloneDXXML serializes a CycloneDX SBOM to XML bytes.
func SerializeCycloneDXXML(bom *CycloneDXBOM) ([]byte, error) {
	var buf bytes.Buffer

	encoder := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatXML)
	if err := encoder.Encode(bom); err != nil {
		return nil, fmt.Errorf("serialize cyclonedx xml: %w", err)
	}

	return buf.Bytes(), nil
}

// SerializeSPDXJSON serializes an SPDX SBOM to JSON bytes.
func SerializeSPDXJSON(doc *SPDXBOM) ([]byte, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("serialize spdx json: %w", err)
	}

	return data, nil
}

// SerializeSPDXTagValue serializes an SPDX SBOM to tag-value (text) format.
func SerializeSPDXTagValue(doc *SPDXBOM) ([]byte, error) {
	var buf bytes.Buffer
	if err := tagvalue.Write(doc, &buf); err != nil {
		return nil, fmt.Errorf("serialize spdx tag-value: %w", err)
	}

	return buf.Bytes(), nil
}

// SerializeInTotoBundle serializes DSSE envelopes to in-toto bundle (JSON Lines) format.
func SerializeInTotoBundle(envelopes []*DSSEEnvelope) ([]byte, error) {
	var buf bytes.Buffer

	for i, env := range envelopes {
		data, err := SerializeDSSEEnvelope(env)
		if err != nil {
			return nil, fmt.Errorf("serialize in-toto bundle envelope %d: %w", i+1, err)
		}

		buf.Write(data)
		buf.WriteByte('\n')
	}

	return buf.Bytes(), nil
}

/*
  sig, err := static.NewSignature(
      payload,      // []byte - the SimpleSigning JSON
      b64sig,       // string - base64-encoded signature
      static.WithCertChain(certPEM, chainPEM),
      static.WithBundle(rekorBundle),
  )

func SimpleClaimVerifier(sig oci.Signature, imageDigest v1.Hash, annotations map[string]interface{}) error
*/
