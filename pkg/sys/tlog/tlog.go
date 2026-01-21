package tlog

import (
	"context"
	"net/url"
	"time"

	"github.com/farcloser/quark/pkg/core/sshprime"
	v1 "github.com/farcloser/quark/pkg/sys/tlog/internal/v1"
)

// Hash represents the unique identifier of an entry in the log.
type Hash = string

// An Operator is an actant in the tlog who can sign event entries.
// Operators may be admin (allowing them to trust or revoke other operators).
// An operator must have a cryptographic identity (either an ssh key or an OIDC identity).
// An operator may be trusted, starting with a Hash position in the tree, possibly ending with another Hash.
// An operator with an End hash has been revoked.
// An operator with no Start hash is unknown (and should not be trusted, obviously).
type Operator struct {
	// SSH-based signer fields
	PublicKey sshprime.Key `json:"public_key,omitempty"` //nolint:tagliatelle // snake_case is intentional for JSON format

	// Keyless/OIDC-based signer fields
	Issuer  *url.URL `json:"issuer,omitempty"`
	Subject string   `json:"subject,omitempty"`

	// Whether the operator is admin or not.
	IsAdmin bool

	// Trusted between commits Start and End
	Start Hash
	End   Hash
}

// An Entity is the subject of an Event, being signed by an Operator.
// It has a descriptor (for example: `ghcr.io/me/mything:tag`).
// It also has a digest, which can be used for example for tag resolution for OCI images.
type Entity struct {
	Descriptor string
	Digest     string
}

// TrustLevel describes the relative trust for an event.
// This is derived from the operator granted trust for the position of that event in the tree.
type TrustLevel string

var (
	Trusted TrustLevel = "trusted"
	Revoked TrustLevel = "revoked"
	Missing TrustLevel = "missing"
)

// An Event is a cryptographically sealed enveloppe stating that a certain Operator has signed an Entity.
type Event struct {
	// Operator who signed the event.
	Operator *Operator
	// Entity being attested.
	Entity *Entity

	// The trust characteristic of the operator for that event position in the tree.
	Trust TrustLevel

	// Hash represent the unique identifier / position in the tlog tree.
	Hash Hash

	// Date is self-reported on the event by the operator.
	// Note that it cannot be trusted, and is not guaranteed to reflect tree order.
	// It is merely indicative, and a malicious event may very well set this out of wack.
	Date time.Time
}

type EventSeq func(yield func(*Event, error) bool)

// An AdmissionLog allows the consumer to quickly resolve and verify entities.
// Typical scenario. "Must install registry/image:tag"
// - GetLastValidEvent("registry/image:tag", ""), returns the last Event for that QIX image that was attested by a
// trusted Operator. This is very much tag->digest resolution, without needing to query an OCI registry.
// - the QIX might link further resources by digest - resolution is no longer an issue, but verifi
type AdmissionLog interface {
	GetLastValidEvent(entity, optionalDigest string) Event
}

type SignerLog interface {
	AddEvent(ctx context.Context, entity, digest string) (string, error)
}

type ManagerLog interface {
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
}

type AuditLog interface {
	OperatorByFingerprint(fingerprint string) *Operator
	OperatorByOIDC(issuer, subject string) *Operator
	Identities() []*Operator
	Event(hash Hash) *Event
	EventsFor(entity, optionalDigest string) EventSeq
	EventsBy(operatorID string, filter TrustLevel) EventSeq
	EventsBetween(hash1, hash2 Hash) EventSeq
	Events() EventSeq

	// Ready-made helpers for anomalies
	BoogieDates() EventSeq
	BoogieUntrustedOperators() []*Operator
	BoogieRevokedEvents() EventSeq
	BoogieUntrustedEvents() EventSeq
}

func NewLog() *logV1 {
	return &logV1{}
}

type logV1 struct {
}

/*
  func (l *logV1) Events() EventSeq {
      return func(yield func(*Event, error) bool) {
          iter, err := l.backend.ListEvents()
          if err != nil {
              yield(nil, err)
              return
          }
          defer iter.Close()  // cleanup when yield returns false or loop ends

          for {
              commit, err := iter.Next()
              if err == io.EOF {
                  return
              }
              if err != nil {
                  yield(nil, err)
                  return
              }
              event := parseEvent(commit)
              if !yield(event, nil) {
   \               return  // caller broke out of loop
              }
          }
      }
  }
*/
