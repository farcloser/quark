package derp

import (
	"encoding/json"

	"github.com/farcloser/quark/pkg/sys/tlog/internal/v1"
)

// CurrentVersion is the current tlog schema version.
// This is set automatically when creating a new log.
const CurrentVersion = 1

// Entry type constants.
const (
	TypeGenesis      = "genesis"
	TypeTrustAdmin   = "trust_admin"   //nolint:gosec // not a credential
	TypeTrustSigner  = "trust_signer"  //nolint:gosec // not a credential
	TypeRevokeAdmin  = "revoke_admin"  //nolint:gosec // not a credential
	TypeRevokeSigner = "revoke_signer" //nolint:gosec // not a credential
	TypeEvent        = "event"
)

// GenesisEntry is the first entry in a log, establishing the initial admin.
type GenesisEntry struct {
	Version  int       `json:"version"`
	Operator v1.Signer `json:"operator"`
}

// MarshalJSON implements json.Marshaler.
func (e *GenesisEntry) MarshalJSON() ([]byte, error) {
	type alias GenesisEntry

	return json.Marshal(struct {
		Type string `json:"type"`
		*alias
	}{
		Type:  TypeGenesis,
		alias: (*alias)(e),
	})
}

// EventEntry records a signed event for an entity with its digest.
type EventEntry struct {
	Entity string `json:"entity"`
	Digest string `json:"digest"`
}

// MarshalJSON implements json.Marshaler.
func (e *EventEntry) MarshalJSON() ([]byte, error) {
	type alias EventEntry

	return json.Marshal(struct {
		Type string `json:"type"`
		*alias
	}{
		Type:  TypeEvent,
		alias: (*alias)(e),
	})
}

// TrustAdminEntry grants admin privileges to an operator.
type TrustAdminEntry struct {
	Operator v1.Signer `json:"operator"`
}

// MarshalJSON implements json.Marshaler.
func (e *TrustAdminEntry) MarshalJSON() ([]byte, error) {
	type alias TrustAdminEntry

	return json.Marshal(struct {
		Type string `json:"type"`
		*alias
	}{
		Type:  TypeTrustAdmin,
		alias: (*alias)(e),
	})
}

// TrustSignerEntry grants signer privileges (can sign events).
type TrustSignerEntry struct {
	Operator v1.Signer `json:"operator"`
}

// MarshalJSON implements json.Marshaler.
func (e *TrustSignerEntry) MarshalJSON() ([]byte, error) {
	type alias TrustSignerEntry

	return json.Marshal(struct {
		Type string `json:"type"`
		*alias
	}{
		Type:  TypeTrustSigner,
		alias: (*alias)(e),
	})
}

// RevokeAdminEntry revokes admin privileges from an operator.
type RevokeAdminEntry struct {
	OperatorID       string `json:"operator_id"` //nolint:tagliatelle // snake_case is intentional for JSON format
	Reason           string `json:"reason,omitempty"`
	EntriesValidUpTo string `json:"entries_valid_up_to,omitempty"` //nolint:tagliatelle // snake_case is intentional for JSON format
}

// MarshalJSON implements json.Marshaler.
func (e *RevokeAdminEntry) MarshalJSON() ([]byte, error) {
	type alias RevokeAdminEntry

	return json.Marshal(struct {
		Type string `json:"type"`
		*alias
	}{
		Type:  TypeRevokeAdmin,
		alias: (*alias)(e),
	})
}

// RevokeSignerEntry revokes signer privileges from an operator.
type RevokeSignerEntry struct {
	OperatorID       string `json:"operator_id"` //nolint:tagliatelle // snake_case is intentional for JSON format
	Reason           string `json:"reason,omitempty"`
	EntriesValidUpTo string `json:"entries_valid_up_to,omitempty"` //nolint:tagliatelle // snake_case is intentional for JSON format
}

// MarshalJSON implements json.Marshaler.
func (e *RevokeSignerEntry) MarshalJSON() ([]byte, error) {
	type alias RevokeSignerEntry

	return json.Marshal(struct {
		Type string `json:"type"`
		*alias
	}{
		Type:  TypeRevokeSigner,
		alias: (*alias)(e),
	})
}
