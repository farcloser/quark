package v1

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/farcloser/quark/pkg/fault"
	"github.com/farcloser/quark/pkg/sys/tlog"
	"github.com/farcloser/quark/pkg/sys/tlog/internal"
	"github.com/farcloser/quark/pkg/sys/tlog/internal/cache"
)

// trustState represents the cached authorization state of the log.
// It is built by walking the log once and supports efficient O(1) lookups
// for verification queries. The struct is JSON-serializable for persistence.
type trustState struct {
	// HeadSHA is the commit hash at which this state was computed.
	HeadSHA string `json:"head_sha"`

	// Records holds authorization records indexed by OperatorID.
	Records map[string]*trustRecord `json:"records"`

	// ByFingerprint maps SSH key fingerprints to OperatorIDs for fast lookup.
	ByFingerprint map[string]string `json:"by_fingerprint"`

	// ByOIDC maps "issuer|subject" to OperatorIDs for keyless operator lookup.
	ByOIDC map[string]string `json:"by_oidc"`
}

// trustRecord holds the authorization state for a single operator.
type trustRecord struct {
	OperatorID string `json:"operator_id"`
	Operator   Signer `json:"operator"`

	// Admin privilege state
	AdminTrusted      bool   `json:"admin_trusted,omitzero"`
	AdminTrustSeen    bool   `json:"admin_trust_seen,omitzero"` // true after we've seen a trust entry (walking newest-first)
	AdminRevoked      bool   `json:"admin_revoked,omitzero"`
	AdminValidUpTo    string `json:"admin_valid_up_to,omitempty"` // commit hash for grandfathering
	AdminRevokeReason string `json:"admin_revoke_reason,omitempty"`
	AdminFromGenesis  bool   `json:"admin_from_genesis,omitzero"` // true if trust comes from genesis

	// Signer privilege state
	SignerTrusted      bool   `json:"signer_trusted,omitzero"`
	SignerTrustSeen    bool   `json:"signer_trust_seen,omitzero"` // true after we've seen a trust entry
	SignerRevoked      bool   `json:"signer_revoked,omitzero"`
	SignerValidUpTo    string `json:"signer_valid_up_to,omitempty"` // commit hash for grandfathering
	SignerRevokeReason string `json:"signer_revoke_reason,omitempty"`
}

// processEntry updates the trust state based on a log entry.
// Entries are processed newest-first.
func (s *trustState) processEntry(entry Entry) {
	switch e := entry.(type) {
	case *tlog.GenesisEntry:
		s.processGenesis(e)
	case *tlog.TrustAdminEntry:
		s.processTrustAdmin(e)
	case *tlog.TrustSignerEntry:
		s.processTrustSigner(e)
	case *tlog.RevokeAdminEntry:
		s.processRevokeAdmin(e)
	case *tlog.RevokeSignerEntry:
		s.processRevokeSigner(e)
		// EventEntry doesn't affect trust state
	}
}

func (s *trustState) getOrCreateRecord(id string) *trustRecord {
	record, exists := s.Records[id]
	if !exists {
		record = &trustRecord{OperatorID: id}
		s.Records[id] = record
	}

	return record
}

func (s *trustState) indexOperator(operator Signer) {
	if operator.PublicKey != "" {
		s.ByFingerprint[operator.PublicKey] = operator.ID
	}

	if operator.Issuer != "" && operator.Subject != "" {
		key := operator.Issuer + "|" + operator.Subject
		s.ByOIDC[key] = operator.ID
	}
}

func (s *trustState) processGenesis(entry *tlog.GenesisEntry) {
	record := s.getOrCreateRecord(entry.Operator.ID)
	// Genesis is oldest, we see it last when walking newest-first
	// Always set trust (it won't have been set by anything newer)
	record.Operator = entry.Operator
	record.AdminTrusted = true
	record.AdminFromGenesis = true
	s.indexOperator(entry.Operator)
}

func (s *trustState) processTrustAdmin(entry *tlog.TrustAdminEntry) {
	record := s.getOrCreateRecord(entry.Operator.ID)
	// Walking newest-first: only record if not already seen
	// (first seen = most recent in log order)
	if !record.AdminTrustSeen {
		record.Operator = entry.Operator
		record.AdminTrusted = true
		record.AdminTrustSeen = true
		s.indexOperator(entry.Operator)
	}
}

func (s *trustState) processTrustSigner(entry *tlog.TrustSignerEntry) {
	record := s.getOrCreateRecord(entry.Operator.ID)

	if !record.SignerTrustSeen {
		record.Operator = entry.Operator
		record.SignerTrusted = true
		record.SignerTrustSeen = true
		s.indexOperator(entry.Operator)
	}
}

func (s *trustState) processRevokeAdmin(entry *tlog.RevokeAdminEntry) {
	record := s.getOrCreateRecord(entry.OperatorID)
	// Walking newest-first: only record first (most recent) revocation
	if !record.AdminRevoked {
		record.AdminRevoked = true
		record.AdminValidUpTo = entry.EntriesValidUpTo
		record.AdminRevokeReason = entry.Reason
	}
}

func (s *trustState) processRevokeSigner(entry *tlog.RevokeSignerEntry) {
	record := s.getOrCreateRecord(entry.OperatorID)

	if !record.SignerRevoked {
		record.SignerRevoked = true
		record.SignerValidUpTo = entry.EntriesValidUpTo
		record.SignerRevokeReason = entry.Reason
	}
}

// isAdminAuthorized checks if a signer matching the given criteria
// was authorized as admin. The entryHash is the commit being verified.
// ancestorCheck is a function that returns true if first arg is an ancestor of (or equal to) second arg.
func (s *trustState) isAdminAuthorized(match internal.EventSigner, entryHash string, ancestorCheck func(hash, ancestor string) (bool, error)) (*tlog.VerifyResult, error) {
	record := s.findRecord(match)
	if record == nil {
		return nil, fmt.Errorf("%w: no matching signer found", tlog.ErrSignerNotTrusted)
	}

	return s.checkAdminAuth(record, entryHash, ancestorCheck)
}

// isSignerAuthorized checks if a signer matching the given criteria
// was authorized as signer. The entryHash is the commit being verified.
// ancestorCheck is a function that returns true if first arg is an ancestor of (or equal to) second arg.
func (s *trustState) isSignerAuthorized(match internal.EventSigner, entryHash string, ancestorCheck func(hash, ancestor string) (bool, error)) (*tlog.VerifyResult, error) {
	record := s.findRecord(match)
	if record == nil {
		return nil, fmt.Errorf("%w: no matching signer found", tlog.ErrSignerNotTrusted)
	}

	return s.checkSignerAuth(record, entryHash, ancestorCheck)
}

func (s *trustState) findRecord(match internal.EventSigner) *trustRecord {
	// Try fingerprint lookup
	if match.Fingerprint != "" {
		if id, ok := s.ByFingerprint[match.Fingerprint]; ok {
			return s.Records[id]
		}
	}

	// Try OIDC lookup
	if match.Issuer != "" && match.Subject != "" {
		key := match.Issuer + "|" + match.Subject
		if id, ok := s.ByOIDC[key]; ok {
			return s.Records[id]
		}
	}

	return nil
}

func (s *trustState) checkAdminAuth(record *trustRecord, entryHash string, ancestorCheck func(hash, ancestor string) (bool, error)) (*tlog.VerifyResult, error) {
	// Case: revocation without prior trust (invalid)
	if record.AdminRevoked && !record.AdminTrusted {
		return nil, fmt.Errorf("%w: revocation without prior trust", tlog.ErrSignerNotTrusted)
	}

	// Case: not trusted as admin
	if !record.AdminTrusted {
		return nil, fmt.Errorf("%w: not trusted as admin", tlog.ErrSignerNotTrusted)
	}

	// Case: trusted but then revoked
	if record.AdminRevoked {
		// Check grandfathering: is the entry at or before the validUpTo commit?
		if record.AdminValidUpTo != "" {
			isAncestor, err := ancestorCheck(entryHash, record.AdminValidUpTo)
			if err != nil {
				return nil, fmt.Errorf("ancestry check failed: %w", err)
			}

			if isAncestor || entryHash == record.AdminValidUpTo {
				return &tlog.VerifyResult{
					OperatorID:    record.OperatorID,
					Trusted:       true,
					TrustSource:   s.adminTrustSource(record),
					Revoked:       true,
					RevokedReason: record.AdminRevokeReason,
				}, nil
			}
		}

		return nil, fmt.Errorf("%w: admin %s was revoked: %s",
			tlog.ErrSignerRevoked, record.OperatorID, record.AdminRevokeReason)
	}

	// Case: trusted and not revoked
	return &tlog.VerifyResult{
		OperatorID:  record.OperatorID,
		Trusted:     true,
		TrustSource: s.adminTrustSource(record),
	}, nil
}

func (s *trustState) checkSignerAuth(record *trustRecord, entryHash string, ancestorCheck func(hash, ancestor string) (bool, error)) (*tlog.VerifyResult, error) {
	// Case: revocation without prior trust (invalid)
	if record.SignerRevoked && !record.SignerTrusted {
		return nil, fmt.Errorf("%w: revocation without prior trust", tlog.ErrSignerNotTrusted)
	}

	// Case: not trusted as signer
	if !record.SignerTrusted {
		return nil, fmt.Errorf("%w: not trusted as signer", tlog.ErrSignerNotTrusted)
	}

	// Case: trusted but then revoked
	if record.SignerRevoked {
		// Check grandfathering: is the entry at or before the validUpTo commit?
		if record.SignerValidUpTo != "" {
			isAncestor, err := ancestorCheck(entryHash, record.SignerValidUpTo)
			if err != nil {
				return nil, fmt.Errorf("ancestry check failed: %w", err)
			}

			if isAncestor || entryHash == record.SignerValidUpTo {
				return &tlog.VerifyResult{
					OperatorID:    record.OperatorID,
					Trusted:       true,
					TrustSource:   tlog.TrustSourceTrustSigner,
					Revoked:       true,
					RevokedReason: record.SignerRevokeReason,
				}, nil
			}
		}

		return nil, fmt.Errorf("%w: signer %s was revoked: %s",
			tlog.ErrSignerRevoked, record.OperatorID, record.SignerRevokeReason)
	}

	// Case: trusted and not revoked
	return &tlog.VerifyResult{
		OperatorID:  record.OperatorID,
		Trusted:     true,
		TrustSource: tlog.TrustSourceTrustSigner,
	}, nil
}

func (s *trustState) adminTrustSource(record *trustRecord) tlog.TrustSource {
	if record.AdminFromGenesis {
		return tlog.TrustSourceGenesis
	}

	return tlog.TrustSourceTrustAdmin
}

// processNewEntry handles entries from incremental updates.
// New entries are more recent than cached state, so they take precedence.
func (s *trustState) processNewEntry(entry Entry) {
	switch e := entry.(type) {
	case *tlog.TrustAdminEntry:
		s.processNewTrustAdmin(e)
	case *tlog.TrustSignerEntry:
		s.processNewTrustSigner(e)
	case *tlog.RevokeAdminEntry:
		s.processNewRevokeAdmin(e)
	case *tlog.RevokeSignerEntry:
		s.processNewRevokeSigner(e)
		// GenesisEntry shouldn't appear in incremental updates
		// EventEntry doesn't affect trust state
	}
}

func (s *trustState) processNewTrustAdmin(entry *tlog.TrustAdminEntry) {
	record := s.getOrCreateRecord(entry.Operator.ID)
	// New trust is more recent - update if no existing trust recorded
	// (with no re-trust rule, this should only happen for new operators)
	if !record.AdminTrusted && !record.AdminRevoked {
		record.Operator = entry.Operator
		record.AdminTrusted = true
		record.AdminTrustSeen = true
		s.indexOperator(entry.Operator)
	}
}

func (s *trustState) processNewTrustSigner(entry *tlog.TrustSignerEntry) {
	record := s.getOrCreateRecord(entry.Operator.ID)

	if !record.SignerTrusted && !record.SignerRevoked {
		record.Operator = entry.Operator
		record.SignerTrusted = true
		record.SignerTrustSeen = true
		s.indexOperator(entry.Operator)
	}
}

func (s *trustState) processNewRevokeAdmin(entry *tlog.RevokeAdminEntry) {
	record := s.getOrCreateRecord(entry.OperatorID)
	// New revocation is more recent - always update
	// (replaces any cached revocation, which shouldn't exist with no re-trust)
	record.AdminRevoked = true
	record.AdminValidUpTo = entry.EntriesValidUpTo
	record.AdminRevokeReason = entry.Reason
}

func (s *trustState) processNewRevokeSigner(entry *tlog.RevokeSignerEntry) {
	record := s.getOrCreateRecord(entry.OperatorID)
	record.SignerRevoked = true
	record.SignerValidUpTo = entry.EntriesValidUpTo
	record.SignerRevokeReason = entry.Reason
}

// Persistence helpers

// loadOrBuildTrustState loads cached state if available, updates it if needed,
// or builds from scratch. Always saves the result.
func LoadTrustState(tlog tlog.Log, repoPath string) (*trustState, error) {
	// Try to load existing cache
	stateData, err := cache.Load(repoPath)
	if err != nil {
		return nil, err
	}

	var state *trustState
	if err = json.Unmarshall(stateData, &state); err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrInvalidJSON, err)
	}

	if state != nil {
		// Try incremental update
		err = updateTrustState(state, tlog)
		if err == nil {
			// Save updated state
			stateData, err = json.Marshall(state)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", fault.ErrInvalidJSON, err)
			}

			if saveErr := cache.Save(repoPath, stateData); saveErr != nil {
				// Log but don't fail - state is still valid
				_ = saveErr
			}

			return state, nil
		}

		if !errors.Is(err, errCacheStale) {
			return nil, err
		}
		// Cache stale, fall through to full rebuild
	}

	// Build from scratch
	state, err = buildTrustState(tlog)
	if err != nil {
		return nil, err
	}

	// Save new state
	stateData, err = json.Marshall(state)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrInvalidJSON, err)
	}

	if err := cache.Save(repoPath, stateData); err != nil {
		// Log but don't fail - state is still valid
		_ = err
	}

	return state, nil
}

// updateTrustState incrementally updates a trustState from its cached HEAD to current HEAD.
// Returns errCacheStale if the cached HEAD is not an ancestor of current HEAD (force-push detected).
// In that case, caller should do a full rebuild with buildTrustState.
func updateTrustState(state *trustState, tlog tlog.Log) error {
	currentHead, err := tlog.Head()
	if err != nil {
		return fmt.Errorf("get HEAD: %w", err)
	}

	// Already up to date
	if state.HeadSHA == currentHead {
		return nil
	}

	// Check if cached HEAD is ancestor of current HEAD
	isAncestor, err := tlog.IsAncestor(state.HeadSHA)
	if err != nil {
		return fmt.Errorf("check ancestry: %w", err)
	}

	if !isAncestor {
		return errCacheStale
	}

	// Walk from current HEAD to cached HEAD, collecting new entries
	iter, err := tlog.Entries()
	if err != nil {
		return fmt.Errorf("iterate entries: %w", err)
	}

	for {
		entry, hash, err := iter.Next()
		if errors.Is(err, ErrLogEmpty) {
			break
		}

		if err != nil {
			return fmt.Errorf("read entry: %w", err)
		}

		// Stop when we reach the cached HEAD
		if hash == state.HeadSHA {
			break
		}

		// Process this new entry
		state.processNewEntry(entry)
	}

	state.HeadSHA = currentHead

	return nil
}

// buildTrustState constructs a trustState by walking the entire log.
func buildTrustState(tlog tlog.Log) (*trustState, error) {
	head, err := tlog.Head()
	if err != nil {
		return nil, fmt.Errorf("get HEAD: %w", err)
	}

	state := &trustState{
		HeadSHA:       head,
		Records:       make(map[string]*trustRecord),
		ByFingerprint: make(map[string]string),
		ByOIDC:        make(map[string]string),
	}

	iter, err := tlog.Entries()
	if err != nil {
		return nil, fmt.Errorf("iterate entries: %w", err)
	}

	// Walk log (newest-first) and collect all trust/revocation entries
	for {
		entry, _, err := iter.Next()
		if errors.Is(err, ErrLogEmpty) {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("read entry: %w", err)
		}

		state.processEntry(entry)
	}

	return state, nil
}
