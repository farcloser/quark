package derp

import (
	"errors"
	"fmt"

	"github.com/farcloser/quark/pkg/sys/tlog/internal"
	"github.com/farcloser/quark/pkg/sys/tlog/internal/v1"
)

// TrustSource indicates how a signer became trusted.
type TrustSource string

// Trust source consts.
const (
	TrustSourceGenesis     TrustSource = "genesis"
	TrustSourceTrustAdmin  TrustSource = "trust_admin"
	TrustSourceTrustSigner TrustSource = "trust_signer"
)

// VerifyResult contains the result of operator verification.
type VerifyResult struct {
	// OperatorID is the ID of the matched operator.
	OperatorID string

	// Trusted indicates whether the operator is trusted.
	Trusted bool

	// TrustSource indicates how the operator was established as trusted.
	TrustSource TrustSource

	// Revoked indicates whether the operator has been revoked.
	Revoked bool

	// RevokedReason is the reason for revocation, if revoked.
	RevokedReason string
}

// revocationInfo holds information about an operator revocation.
type revocationInfo struct {
	operatorID       string
	reason           string
	entriesValidUpTo string // commit hash for grandfathering
}

// operatorWithSource pairs an operator with its trust source.
type operatorWithSource struct {
	operator v1.Signer
	source   TrustSource
}

// logVerifier is an internal interface for verification operations.
// It provides the minimal set of operations needed by verify functions.
type logVerifier interface {
	Entries() (EntryIterator, error)
	isAncestorOf(hash, ancestor string) (bool, error)
}

// verifySigner verifies that a EventSigner corresponds to a trusted signer
// (has signer privileges). entryHash is the commit being verified.
// It walks the log to find matching operators with signer privileges and checks for revocations.
func verifySigner(l logVerifier, match internal.EventSigner, entryHash string) (*VerifyResult, error) {
	// Collect revocations and trusted signers by walking the log
	signerRevocations := make(map[string]*revocationInfo)
	trustedSigners := make([]operatorWithSource, 0)

	iter, err := l.Entries()
	if err != nil {
		return nil, fmt.Errorf("failed to iterate entries: %w", err)
	}

	for {
		entry, _, err := iter.Next()
		if errors.Is(err, ErrLogEmpty) {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("failed to read entry: %w", err)
		}

		switch typed := entry.(type) {
		case *RevokeSignerEntry:
			// Only record first revocation (newest takes precedence)
			if _, exists := signerRevocations[typed.OperatorID]; !exists {
				signerRevocations[typed.OperatorID] = &revocationInfo{
					operatorID:       typed.OperatorID,
					reason:           typed.Reason,
					entriesValidUpTo: typed.EntriesValidUpTo,
				}
			}
		case *TrustSignerEntry:
			trustedSigners = append(trustedSigners, operatorWithSource{
				operator: typed.Operator,
				source:   TrustSourceTrustSigner,
			})
		case *GenesisEntry:
			// Genesis admin is NOT automatically a signer
			// They must TrustSigner themselves if they want to sign events
			_ = typed // genesis only establishes admin, not signer
		}
	}

	// Find a matching trusted signer
	for idx := range trustedSigners {
		ows := &trustedSigners[idx]
		if !ows.operator.Matches(match) {
			continue
		}

		// Found a match - check for revocation
		result := &VerifyResult{
			OperatorID:  ows.operator.ID,
			Trusted:     true,
			TrustSource: ows.source,
		}

		if revInfo, revoked := signerRevocations[ows.operator.ID]; revoked {
			// Check grandfathering: is the entry at or before the validUpTo commit?
			if revInfo.entriesValidUpTo != "" {
				isAncestor, err := l.isAncestorOf(entryHash, revInfo.entriesValidUpTo)
				if err != nil {
					return nil, fmt.Errorf("ancestry check failed: %w", err)
				}

				if isAncestor || entryHash == revInfo.entriesValidUpTo {
					// Entry is grandfathered - still trusted but note revocation
					result.Revoked = true
					result.RevokedReason = revInfo.reason

					return result, nil
				}
			}

			// Not grandfathered - revocation applies
			return nil, fmt.Errorf(
				"%w: signer %s was revoked: %s",
				ErrSignerRevoked,
				ows.operator.ID,
				revInfo.reason,
			)
		}

		return result, nil
	}

	return nil, fmt.Errorf("%w: no matching signer found", ErrSignerNotTrusted)
}

// verifyAdmin verifies that a EventSigner corresponds to a trusted admin.
// entryHash is the commit being verified.
// It walks the log to find matching operators with admin privileges and checks for revocations.
func verifyAdmin(l logVerifier, match internal.EventSigner, entryHash string) (*VerifyResult, error) {
	// Collect revocations and trusted admins by walking the log
	adminRevocations := make(map[string]*revocationInfo)
	trustedAdmins := make([]operatorWithSource, 0)

	iter, err := l.Entries()
	if err != nil {
		return nil, fmt.Errorf("failed to iterate entries: %w", err)
	}

	for {
		entry, _, err := iter.Next()
		if errors.Is(err, ErrLogEmpty) {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("failed to read entry: %w", err)
		}

		switch typed := entry.(type) {
		case *RevokeAdminEntry:
			// Only record first revocation (newest takes precedence)
			if _, exists := adminRevocations[typed.OperatorID]; !exists {
				adminRevocations[typed.OperatorID] = &revocationInfo{
					operatorID:       typed.OperatorID,
					reason:           typed.Reason,
					entriesValidUpTo: typed.EntriesValidUpTo,
				}
			}
		case *TrustAdminEntry:
			trustedAdmins = append(trustedAdmins, operatorWithSource{
				operator: typed.Operator,
				source:   TrustSourceTrustAdmin,
			})
		case *GenesisEntry:
			// Genesis establishes the initial admin
			trustedAdmins = append(trustedAdmins, operatorWithSource{
				operator: typed.Operator,
				source:   TrustSourceGenesis,
			})
		}
	}

	// Find a matching trusted admin
	for idx := range trustedAdmins {
		ows := &trustedAdmins[idx]
		if !ows.operator.Matches(match) {
			continue
		}

		// Found a match - check for revocation
		result := &VerifyResult{
			OperatorID:  ows.operator.ID,
			Trusted:     true,
			TrustSource: ows.source,
		}

		if revInfo, revoked := adminRevocations[ows.operator.ID]; revoked {
			// Check grandfathering: is the entry at or before the validUpTo commit?
			if revInfo.entriesValidUpTo != "" {
				isAncestor, err := l.isAncestorOf(entryHash, revInfo.entriesValidUpTo)
				if err != nil {
					return nil, fmt.Errorf("ancestry check failed: %w", err)
				}

				if isAncestor || entryHash == revInfo.entriesValidUpTo {
					// Entry is grandfathered - still trusted but note revocation
					result.Revoked = true
					result.RevokedReason = revInfo.reason

					return result, nil
				}
			}

			// Not grandfathered - revocation applies
			return nil, fmt.Errorf(
				"%w: admin %s was revoked: %s",
				ErrSignerRevoked,
				ows.operator.ID,
				revInfo.reason,
			)
		}

		return result, nil
	}

	return nil, fmt.Errorf("%w: no matching admin found", ErrSignerNotTrusted)
}
