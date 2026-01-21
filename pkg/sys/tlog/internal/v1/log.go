package v1

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/farcloser/quark/pkg/sys/tlog"
	"github.com/farcloser/quark/pkg/sys/tlog/internal"
	"github.com/farcloser/quark/pkg/sys/tlog/internal/storage"
)

// EntryIterator iterates over log entries.
type EntryIterator interface {
	// Next returns the next entry and its commit hash.
	// Returns ErrLogEmpty when there are no more entries.
	Next() (Entry, string, error)
}

type Log interface {
	EventsFor(entity string) (tlog.EntryIterator, error)
}

// logV1 implements Log for schema version 1.
type logV1 struct {
	repo   *storage.Backend
	config *tlog.config
}

// Ensure logV1 implements Log.
var _ tlog.Log = (*logV1)(nil)

// Head returns the current HEAD commit hash.
func (l *logV1) Head() (string, error) {
	head, err := l.repo.Head()
	if err != nil {
		return "", fmt.Errorf("failed to get HEAD: %w", err)
	}

	return head, nil
}

// Event adds an event entry for an entity.
func (l *logV1) Event(_ context.Context, entity, digest string) (string, error) {
	if err := l.requireSigner(); err != nil {
		return "", err
	}

	entry := &tlog.EventEntry{
		Entity: entity,
		Digest: digest,
	}

	return l.createCommit(entry)
}

//// TrustAdmin grants admin privileges to an operator.
//func (l *logV1) TrustAdmin(_ context.Context, operator Signer) (string, error) {
//	if err := l.requireAdmin(); err != nil {
//		return "", err
//	}
//
//	if err := operator.Validate(); err != nil {
//		return "", err
//	}
//
//	entry := &tlog.TrustAdminEntry{
//		Operator: operator,
//	}
//
//	return l.createCommit(entry)
//}
//
//// TrustSigner grants signer privileges to an operator.
//func (l *logV1) TrustSigner(_ context.Context, operator Signer) (string, error) {
//	if err := l.requireAdmin(); err != nil {
//		return "", err
//	}
//
//	if err := operator.Validate(); err != nil {
//		return "", err
//	}
//
//	entry := &tlog.TrustSignerEntry{
//		Operator: operator,
//	}
//
//	return l.createCommit(entry)
//}
//
//// RevokeAdmin revokes admin privileges from an operator.
//func (l *logV1) RevokeAdmin(_ context.Context, operatorID, reason, validUpTo string) (string, error) {
//	if err := l.requireAdmin(); err != nil {
//		return "", err
//	}
//
//	if operatorID == "" {
//		return "", fmt.Errorf("%w: operator ID is required", tlog.ErrInvalidEntry)
//	}
//
//	entry := &tlog.RevokeAdminEntry{
//		OperatorID:       operatorID,
//		Reason:           reason,
//		EntriesValidUpTo: validUpTo,
//	}
//
//	return l.createCommit(entry)
//}
//
//// RevokeSigner revokes signer privileges from an operator.
//func (l *logV1) RevokeSigner(_ context.Context, operatorID, reason, validUpTo string) (string, error) {
//	if err := l.requireAdmin(); err != nil {
//		return "", err
//	}
//
//	if operatorID == "" {
//		return "", fmt.Errorf("%w: operator ID is required", tlog.ErrInvalidEntry)
//	}
//
//	entry := &tlog.RevokeSignerEntry{
//		OperatorID:       operatorID,
//		Reason:           reason,
//		EntriesValidUpTo: validUpTo,
//	}
//
//	return l.createCommit(entry)
//}

// Latest returns the latest event entry for an entity.
func (l *logV1) Latest(entity string) (*tlog.EventEntry, string, error) {
	iter, err := l.EventsFor(entity)
	if err != nil {
		return nil, "", err
	}

	for {
		entry, hash, err := iter.Next()
		if errors.Is(err, tlog.ErrLogEmpty) {
			break
		}

		if err != nil {
			return nil, "", err
		}

		if event, ok := entry.(*tlog.EventEntry); ok {
			return event, hash, nil
		}
	}

	return nil, "", fmt.Errorf("%w: no events for entity %s", tlog.ErrLogEmpty, entity)
}

// Entries returns an iterator over all entries (newest first).
func (l *logV1) Entries() (tlog.EntryIterator, error) {
	commits, err := l.repo.ListEvents()
	if err != nil {
		return nil, fmt.Errorf("failed to get commits: %w", err)
	}

	return &entryIterV1{
		commits:    commits,
		parseEntry: tlog.parseEntry,
	}, nil
}

// EventsFor returns an iterator over events for a specific entity.
func (l *logV1) EventsFor(entity string) (tlog.EntryIterator, error) {
	commits, err := l.repo.ListEvents()
	if err != nil {
		return nil, fmt.Errorf("failed to get commits: %w", err)
	}

	return &entryIterV1{
		commits:      commits,
		parseEntry:   tlog.parseEntry,
		filterEntity: entity,
	}, nil
}

// IsAncestor returns true if ancestor is an ancestor of HEAD.
func (l *logV1) IsAncestor(ancestor string) (bool, error) {
	head, err := l.repo.Head()
	if err != nil {
		return false, err
	}

	isAnc, err := l.repo.IsAncestor(ancestor, head)
	if err != nil {
		return false, err
	}

	return isAnc, nil
}

//// VerifySigner verifies that a EventSigner corresponds to a trusted signer.
//func (l *logV1) VerifySigner(match internal.EventSigner, entryHash string) (*tlog.VerifyResult, error) {
//	return tlog.verifySigner(l, match, entryHash)
//}
//
//// VerifyAdmin verifies that a EventSigner corresponds to a trusted admin.
//func (l *logV1) VerifyAdmin(match internal.EventSigner, entryHash string) (*tlog.VerifyResult, error) {
//	return tlog.verifyAdmin(l, match, entryHash)
//}
//
//// VerifyEntry verifies that a commit is signed by a trusted signer.
//func (l *logV1) VerifyEntry(hash string) (*tlog.VerifyResult, error) {
//	fing, err := l.repo.GetEventSignatureFingerprint(hash)
//	if err != nil {
//		return nil, err
//	}
//
//	match := internal.EventSigner{
//		Fingerprint: fing,
//	}
//
//	return l.VerifySigner(match, hash)
//}

// // Fetch fetches from remote.
//
//	func (l *logV1) Fetch(ctx context.Context) error {
//		return l.repo.Fetch(ctx)
//	}
//
// // Push pushes to remote.
//
//	func (l *logV1) Push(ctx context.Context) error {
//		return l.repo.Push(ctx)
//	}
//
// isAncestorOf checks if hash is an ancestor of (or equal to) ancestor.
// This is used for grandfathering checks.
func (l *logV1) isAncestorOf(hash, ancestor string) (bool, error) {
	return l.repo.IsAncestor(hash, ancestor)
}

// requireAdmin checks that the configured signing key is authorized as admin.
// This is a soft-check to prevent accidental misuse; it does not provide security
// (commits are verified independently by walking the log).
func (l *logV1) requireAdmin() error {
	if l.config.author.Key == nil {
		return tlog.ErrNoSigningKey
	}

	head, err := l.repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get HEAD: %w", err)
	}

	match := internal.EventSigner{
		Fingerprint: l.config.author.Key.Fingerprint(),
	}

	_, err = l.VerifyAdmin(match, head)
	if err != nil {
		return fmt.Errorf("%w: %w", tlog.ErrNotAdmin, err)
	}

	return nil
}

// requireSigner checks that the configured signing key is authorized as signer.
// This is a soft-check to prevent accidental misuse; it does not provide security
// (commits are verified independently by walking the log).
func (l *logV1) requireSigner() error {
	if l.config.author.Key == nil {
		return tlog.ErrNoSigningKey
	}

	head, err := l.repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get HEAD: %w", err)
	}

	match := internal.EventSigner{
		Fingerprint: l.config.author.Key.Fingerprint(),
	}

	_, err = l.VerifySigner(match, head)
	if err != nil {
		return fmt.Errorf("%w: %w", tlog.ErrNotSigner, err)
	}

	return nil
}

func (l *logV1) createCommit(entry Entry) (string, error) {
	entryJSON, err := tlog.marshalEntry(entry)
	if err != nil {
		return "", fmt.Errorf("%w: %w", tlog.ErrInvalidEntry, err)
	}

	hash, err := l.repo.AddEvent(string(entryJSON))
	if err != nil {
		return "", fmt.Errorf("failed to create commit: %w", err)
	}

	return hash, nil
}

// entryIterV1 implements EntryIterator for v1 schema.
type entryIterV1 struct {
	commits      *storage.CommitIter
	parseEntry   func([]byte) (Entry, error)
	filterEntity string
}

func (i *entryIterV1) Next() (Entry, string, error) {
	for {
		commit, err := i.commits.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, "", tlog.ErrLogEmpty
			}

			return nil, "", tlog.ErrLogEmpty
		}

		entry, err := i.parseEntry([]byte(commit.Message))
		if err != nil {
			// Skip malformed entries
			continue
		}

		// Apply entity filter if set
		if i.filterEntity != "" {
			event, ok := entry.(*tlog.EventEntry)
			if !ok || event.Entity != i.filterEntity {
				continue
			}
		}

		return entry, commit.Hash, nil
	}
}
