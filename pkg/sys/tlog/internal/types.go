package internal

// EventSigner represents the identity extracted from a signature for matching
// against trusted Signer entries. It contains either SSH fingerprint info
// or keyless/OIDC identity info.
type EventSigner struct {
	// SSH signature info
	Fingerprint string

	// Keyless/OIDC signature info
	Issuer  string
	Subject string
}

// IsSSH returns true if this match represents an SSH signature.
func (m *EventSigner) IsSSH() bool {
	return m.Fingerprint != ""
}

// IsKeyless returns true if this match represents a keyless/OIDC signature.
func (m *EventSigner) IsKeyless() bool {
	return m.Fingerprint == ""
}

// TrustState represents the interface to the backend store (independent of implementation / version) that can
// answer questions about trustworthiness of entries.
type TrustState interface {
	IsAuthorizedAsAdmin(match EventSigner, entryHash string)
	IsAuthorizedAsSigner(match EventSigner, entryHash string)
}
