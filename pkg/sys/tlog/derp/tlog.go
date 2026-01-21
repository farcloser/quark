package derp

import (
	"context"

	"github.com/farcloser/quark/pkg/sys/tlog/internal"
	"github.com/farcloser/quark/pkg/sys/tlog/internal/v1"
)

// Log is the interface for transparency log operations.
// It abstracts the underlying schema version, allowing different
// implementations for v1, v2, etc.
type Log interface {
	// Head returns the current HEAD commit hash.
	Head() (string, error)

	// Event adds an event entry for an entity.
	// Returns the commit hash.
	Event(ctx context.Context, entity, digest string) (string, error)

	// TrustAdmin grants admin privileges to an operator.
	TrustAdmin(ctx context.Context, operator v1.Signer) (string, error)

	// TrustSigner grants signer privileges to an operator.
	TrustSigner(ctx context.Context, operator v1.Signer) (string, error)

	// RevokeAdmin revokes admin privileges from an operator.
	// validUpTo is a commit hash - entries at or before this commit remain valid.
	RevokeAdmin(ctx context.Context, operatorID, reason, validUpTo string) (string, error)

	// RevokeSigner revokes signer privileges from an operator.
	// validUpTo is a commit hash - entries at or before this commit remain valid.
	RevokeSigner(ctx context.Context, operatorID, reason, validUpTo string) (string, error)

	// Latest returns the latest event entry for an entity.
	Latest(entity string) (*EventEntry, string, error)

	// Entries returns an iterator over all entries (newest first).
	Entries() (EntryIterator, error)

	// EventsFor returns an iterator over events for a specific entity.
	EventsFor(entity string) (EntryIterator, error)

	// VerifySigner verifies that a EventSigner corresponds to a trusted signer.
	VerifySigner(match internal.EventSigner, entryHash string) (*VerifyResult, error)

	// VerifyAdmin verifies that a EventSigner corresponds to a trusted admin.
	VerifyAdmin(match internal.EventSigner, entryHash string) (*VerifyResult, error)

	// VerifyEntry verifies that a commit is signed by a trusted signer.
	VerifyEntry(hash string) (*VerifyResult, error)

	// IsAncestor returns true if ancestor is an ancestor of HEAD.
	IsAncestor(ancestor string) (bool, error)

	// Fetch fetches from remote.
	Fetch(ctx context.Context) error

	// Push pushes to remote.
	Push(ctx context.Context) error
}

// SchemaVersion represents the tlog schema version.
type SchemaVersion int

const (
	// SchemaV1 is the initial schema version.
	SchemaV1 SchemaVersion = 1
)

// CurrentSchema is the schema version used for new logs.
const CurrentSchema = SchemaV1
