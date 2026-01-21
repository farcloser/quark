package sigstore

import (
	"bytes"
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	sigstoresig "github.com/sigstore/sigstore/pkg/signature"

	"github.com/farcloser/quark/internal/types"
	"github.com/farcloser/quark/pkg/core/trust"
)

/*
  | Option                      | Source                            | Purpose                                         |
  |-----------------------------|-----------------------------------|-------------------------------------------------|
  | WithObserverTimestamps(n)   | TSA or Rekor SignedEntryTimestamp | Verify Fulcio cert was valid                    |
  | WithSignedTimestamps(n)     | TSA only (RFC 3161)               | Verify Fulcio cert was valid                    |
  | WithIntegratedTimestamps(n) | Rekor log entry time              | Verify Fulcio cert was valid                    |
  | WithCurrentTime()           | System clock                      | For long-lived certs only (private deployments) |

  | Option                     | Purpose                                     |
  |----------------------------|---------------------------------------------|
  | WithNoObserverTimestamps() | Key verification only - no cert to validate |
*/

type sigstoreBundle struct {
	// Rekor root
	trustedRoot *types.Trusted
	// Holds the annotations from the descriptor
	annotations map[string]string
	// Inner bundle
	bundle *bundle.Bundle
	// Statement
	statement *v1.Statement
	// Artifact payload for MessageSignature bundles (legacy format).
	// Required for verification since the signature was over the raw payload.
	artifact []byte

	// rfc3161Timestamp *time.Time // later...
}

func (sb *sigstoreBundle) Annotations() map[string]string {
	custom := make(map[string]string)

	for key, value := range sb.annotations {
		isReserved := false

		for _, prefix := range reservedAnnotationPrefixes {
			if strings.HasPrefix(key, prefix) {
				isReserved = true

				break
			}
		}

		if !isReserved {
			custom[key] = value
		}
	}

	return custom
}

func (sb *sigstoreBundle) Timestamp() *time.Time {
	if sb.bundle == nil {
		return nil
	}

	entries, err := sb.bundle.TlogEntries()
	if err != nil || len(entries) == 0 {
		return nil
	}

	// Use the first tlog entry's integrated time.
	integratedTime := entries[0].IntegratedTime()

	return &integratedTime
}

func (sb *sigstoreBundle) VerifyWithKey(
	publicKey []byte,
) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %w", types.ErrBundleSignatureVerificationFailed, err)
		}
	}()

	// Create trusted key material from public key and verifier options
	trustedKeys, _, err := bytesToPublicKeyMaterial(publicKey)
	if err != nil {
		return fmt.Errorf("%w: %w", errFailedReadingKey, err)
	}

	trustMaterial := root.TrustedMaterialCollection{trustedKeys}
	verifierOpts := []verify.VerifierOption{}

	// Combine trusted keys with trusted root for Rekor verification.
	if sb.trustedRoot != nil {
		trustMaterial = append(trustMaterial, sb.trustedRoot)
		verifierOpts = append(verifierOpts,
			verify.WithTransparencyLog(1),
			verify.WithIntegratedTimestamps(1),
		)
	} else {
		verifierOpts = append(verifierOpts, verify.WithNoObserverTimestamps())
	}

	signatureVerifier, err := verify.NewVerifier(trustMaterial, verifierOpts...)
	if err != nil {
		return fmt.Errorf("create verifier: %w", err)
	}

	// Build policy options. For MessageSignature bundles (legacy format),
	// we need to provide the artifact since the signature was over the raw payload.
	var artifactOpt verify.ArtifactPolicyOption
	if sb.artifact != nil {
		artifactOpt = verify.WithArtifact(bytes.NewReader(sb.artifact))
	} else {
		artifactOpt = verify.WithoutArtifactUnsafe()
	}

	_, err = signatureVerifier.Verify(sb.bundle, verify.NewPolicy(
		artifactOpt,
		verify.WithKey(),
	))
	if err != nil {
		return fmt.Errorf("%w: %w", errKeyVerificationFailed, err)
	}

	return nil
}

func (sb *sigstoreBundle) Verify() (signerInfo *types.KeylessSignerInfo, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %w: %w", types.ErrBundleSignatureVerificationFailed, errKeyVerificationFailed, err)
		}
	}()

	verifierOpts := []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
	}

	anySignerPolicy, err := verify.NewShortCertificateIdentity("", ".*", "", ".*")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedCreatingPolicy, err)
	}

	signatureVerifier, err := verify.NewVerifier(sb.trustedRoot, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedCreatingVerifier, err)
	}

	result, err := signatureVerifier.Verify(sb.bundle, verify.NewPolicy(
		verify.WithoutArtifactUnsafe(),
		verify.WithCertificateIdentity(anySignerPolicy),
	))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errKeylessVerificationFailed, err)
	}

	if result == nil || result.Signature == nil || result.Signature.Certificate == nil {
		return nil, errVerificationFailedNothing
	}

	cert := result.Signature.Certificate

	return &types.KeylessSignerInfo{
		Subject: cert.SubjectAlternativeName,
		Issuer:  cert.Issuer,
	}, nil
}

// bytesToPublicKeyMaterial creates TrustedPublicKeyMaterial from a PEM-encoded public key.
func bytesToPublicKeyMaterial(publicKeyPEM []byte) (*root.TrustedPublicKeyMaterial, string, error) {
	pubKey, err := trust.PEMToPublicKey(publicKeyPEM)
	if err != nil {
		return nil, "", fmt.Errorf("parse public key: %w", err)
	}

	baseVerifier, err := sigstoresig.LoadVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return nil, "", fmt.Errorf("load verifier: %w", err)
	}

	expiringKey := root.NewExpiringKey(baseVerifier, time.Time{}, time.Time{})

	trustedKeys := root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
		return expiringKey, nil
	})

	return trustedKeys, "", nil
}
