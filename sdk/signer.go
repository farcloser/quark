package sdk

import "strings"

// SignerIdentity represents a trusted signer identity for signature verification.
// Used for keyless (Fulcio) signing where identity is attested via OIDC.
type SignerIdentity struct {
	// Subject is the identity subject pattern (email, OIDC subject, GitHub workflow path).
	// Supports wildcard patterns:
	//   - Exact match: "ci@mycompany.com"
	//   - Prefix match (ends with *): "https://github.com/org/repo/.github/workflows/*"
	Subject string `json:"subject"`

	// Issuer is the OIDC token issuer URL (exact match).
	// Examples: "https://accounts.google.com", "https://token.actions.githubusercontent.com"
	Issuer string `json:"issuer"`
}

// Matches checks if an actual signer matches this trusted identity.
// Subject supports prefix matching when ending with *.
// Issuer requires exact match.
func (s SignerIdentity) Matches(actualSubject, actualIssuer string) bool {
	// Issuer must match exactly.
	if s.Issuer != actualIssuer {
		return false
	}

	// Subject: if ends with *, use prefix match; otherwise exact match.
	if strings.HasSuffix(s.Subject, "*") {
		prefix := strings.TrimSuffix(s.Subject, "*")

		return strings.HasPrefix(actualSubject, prefix)
	}

	return s.Subject == actualSubject
}
