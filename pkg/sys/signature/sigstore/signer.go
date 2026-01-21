package sigstore

import (
	"encoding/json"
	"fmt"

	"github.com/in-toto/attestation/go/v1"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/farcloser/quark/internal/types"
	"github.com/farcloser/quark/pkg/sys/signature/cosign"
)

// NewSigner returns a concrete Signer implementation based on sigstore.
func NewSigner(sigRoot *types.Trusted) types.Signer {
	return &sigstoreSigner{
		sigRoot: sigRoot,
	}
}

type sigstoreSigner struct {
	sigRoot *types.Trusted
}

func (*sigstoreSigner) Sign(types.Digest) types.Signature {
	panic("implement me")
}

func (cs *sigstoreSigner) ReadSignature(
	payload []byte,
	annotations map[string]string,
	mediaType types.MediaType,
) (signature types.Signature, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %w", types.ErrBundleReadFailed, err)
		}
	}()

	// Handle legacy cosign simple signing format.
	if mediaType == layerMediaTypeCosignSignature {
		return cs.readLegacySignature(payload, annotations)
	}

	statement, sigBundle, err := extract(payload, mediaType)
	if err != nil {
		return nil, err
	}

	// If it is not a signature, bail out.
	predicateType := statement.GetPredicateType()
	if predicateType != predicateTypeSignature {
		return nil, fmt.Errorf("%w: %s", errUnrecognizedPredicateType, predicateType)
	}

	return &sigstoreSignature{
		sigstoreBundle: sigstoreBundle{
			annotations: annotations,
			bundle:      sigBundle,
			trustedRoot: cs.sigRoot,
			statement:   statement,
		},
	}, nil
}

func (cs *sigstoreSigner) ReadAttestation(
	payload []byte,
	annotations map[string]string,
	mediaType types.MediaType,
) (attestation types.Attestation, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %w", types.ErrBundleReadFailed, err)
		}
	}()

	// Handle legacy cosign DSSE envelope format.
	if mediaType == layerMediaTypeDSSEEnvelope {
		return cs.readLegacyAttestation(payload, annotations)
	}

	statement, sigBundle, err := extract(payload, mediaType)
	if err != nil {
		return nil, err
	}

	// If it is a signature, bail out.
	predicateType := statement.GetPredicateType()
	if predicateType == predicateTypeSignature {
		return nil, fmt.Errorf("%w: %s", errUnrecognizedPredicateType, predicateType)
	}

	subjects := statement.GetSubject()
	predicate := statement.GetPredicate()

	// Convert from protobuf statement to in-toto-golang statement.
	inStatement := &types.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          statement.GetType(),
			PredicateType: predicateType,
		},
	}

	// Convert subjects.
	for _, subj := range subjects {
		inStatement.Subject = append(inStatement.Subject, in_toto.Subject{
			Name:   subj.GetName(),
			Digest: subj.GetDigest(),
		})
	}

	// Predicate is stored as raw JSON in the protobuf struct.
	if predicate != nil {
		predicateBytes, err := predicate.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errFailedMarshallingPredicate, err)
		}

		inStatement.Predicate = json.RawMessage(predicateBytes)
	}

	return &sigstoreAttestation{
		sigstoreBundle: sigstoreBundle{
			annotations: annotations,
			bundle:      sigBundle,
			trustedRoot: cs.sigRoot,
		},
		statement: inStatement,
	}, nil
}

// readLegacySignature handles legacy cosign simple signing format.
// It converts the payload to a sigstore bundle and creates a synthetic
// in-toto statement from the simple signing payload for subject extraction.
func (cs *sigstoreSigner) readLegacySignature(
	payload []byte,
	annotations map[string]string,
) (types.Signature, error) {
	// Parse the simple signing payload to extract image digest.
	statement, err := cosign.ParseSimpleSigning(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedParsingLegacySignature, err)
	}

	// Convert to sigstore bundle.
	bundleBytes, _, err := cosign.Convert(payload, annotations)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedParsingLegacySignature, err)
	}

	// Parse the bundle (MessageSignature content type).
	sigBundle := &bundle.Bundle{}
	if err := sigBundle.UnmarshalJSON(bundleBytes); err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedParsingBundle, err)
	}

	return &sigstoreSignature{
		sigstoreBundle: sigstoreBundle{
			annotations: annotations,
			bundle:      sigBundle,
			trustedRoot: cs.sigRoot,
			statement:   statement,
			artifact:    payload, // Store for MessageSignature verification
		},
	}, nil
}

// readLegacyAttestation handles legacy cosign DSSE envelope format.
// It wraps the raw DSSE envelope in a sigstore bundle for verification.
func (cs *sigstoreSigner) readLegacyAttestation(
	payload []byte,
	annotations map[string]string,
) (types.Attestation, error) {
	// Convert to sigstore bundle (wraps DSSE envelope with verification material).
	bundleBytes, _, err := cosign.ConvertAttestation(payload, annotations)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedParsingLegacyAttestation, err)
	}

	// Parse the bundle.
	sigBundle := &bundle.Bundle{}
	if err := sigBundle.UnmarshalJSON(bundleBytes); err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedParsingBundle, err)
	}

	// Extract statement from the DSSE envelope.
	envelope, err := sigBundle.Envelope()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedParsingEnvelope, err)
	}

	statement, err := envelope.Statement()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedParsingStatement, err)
	}

	// If it is a signature, bail out.
	predicateType := statement.GetPredicateType()
	if predicateType == predicateTypeSignature {
		return nil, fmt.Errorf("%w: %s", errUnrecognizedPredicateType, predicateType)
	}

	subjects := statement.GetSubject()
	predicate := statement.GetPredicate()

	// Convert from protobuf statement to in-toto-golang statement.
	inStatement := &types.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          statement.GetType(),
			PredicateType: predicateType,
		},
	}

	// Convert subjects.
	for _, subj := range subjects {
		inStatement.Subject = append(inStatement.Subject, in_toto.Subject{
			Name:   subj.GetName(),
			Digest: subj.GetDigest(),
		})
	}

	// Predicate is stored as raw JSON in the protobuf struct.
	if predicate != nil {
		predicateBytes, err := predicate.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errFailedMarshallingPredicate, err)
		}

		inStatement.Predicate = json.RawMessage(predicateBytes)
	}

	return &sigstoreAttestation{
		sigstoreBundle: sigstoreBundle{
			annotations: annotations,
			bundle:      sigBundle,
			trustedRoot: cs.sigRoot,
		},
		statement: inStatement,
	}, nil
}

// extract processes a raw payload and return a bundle and in-toto statement.
func extract(payload []byte, mediaType types.MediaType) (statement *v1.Statement, sigBundle *bundle.Bundle, err error) {
	if mediaType != layerMediaTypeSigstoreBundle {
		return nil, nil, fmt.Errorf("%w: %s", errUnrecognizedMediaType, mediaType)
	}

	sigBundle = &bundle.Bundle{}
	if err := sigBundle.UnmarshalJSON(payload); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errFailedParsingBundle, err)
	}

	envelope, err := sigBundle.Envelope()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errFailedParsingEnvelope, err)
	}

	statement, err = envelope.Statement()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errFailedParsingStatement, err)
	}

	// RFC3161 unsupported
	// timestamps, err := sigBundle.Timestamps()
	// if len(timestamps) > 0 {
	//
	// }

	// Yep, this is redundant, we already know that from the layer descriptor
	// if sigBundle.MediaType != string(layerMediaTypeSigstoreBundle) {
	//	return nil, fmt.Errorf("%w: %s", types.ErrBundleReadFailed, sigBundle.MediaType)
	// }

	// Not particularly useful either
	// if envelope.PayloadType != payloadTypeInToto {
	//	return nil, fmt.Errorf("%w: %s", types.ErrBundleReadFailed, envelope.PayloadType)
	// }

	// Sigstore does it on its own
	// statementType := statement.GetType()
	// if statementType != statementTypeInToto {
	//	return nil, fmt.Errorf("%w: unrecognized statement type: %s", types.ErrBundleReadFailed, statementType)
	// }

	return statement, sigBundle, nil
}
