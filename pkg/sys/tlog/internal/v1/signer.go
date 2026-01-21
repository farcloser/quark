package v1

import (
	"fmt"
	"regexp"

	"github.com/farcloser/quark/pkg/core/sshprime"
	"github.com/farcloser/quark/pkg/sys/tlog/internal"
)

// Signer represents a trusted signer identity that can sign log entries.
// A signer is either SSH-based (KeyType + PublicKey) or keyless/OIDC-based (Issuer + Subject).
type Signer struct {
	// ID is a unique identifier for this signer within the log.
	ID string `json:"id"`

	// SSH-based signer fields
	PublicKey sshprime.Key `json:"public_key,omitempty"` //nolint:tagliatelle // snake_case is intentional for JSON format

	// Keyless/OIDC-based signer fields
	Issuer  string `json:"issuer,omitempty"`
	Subject string `json:"subject,omitempty"`
}

// Validate checks that the signer configuration is valid.
// A signer must have an ID and must be either SSH or keyless, not both or neither.
func (s *Signer) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("%w: missing id", ErrInvalidSigner)
	}

	isSSH := s.PublicKey != nil
	isKeyless := s.Issuer != "" || s.Subject != ""

	if isSSH && isKeyless {
		return fmt.Errorf("%w: cannot specify both SSH and keyless fields", ErrInvalidSigner)
	}

	if !isSSH && !isKeyless {
		return fmt.Errorf("%w: must specify either SSH or keyless fields", ErrInvalidSigner)
	}

	if isKeyless {
		if s.Issuer == "" {
			return fmt.Errorf("%w: keyless signer missing issuer", ErrInvalidSigner)
		}

		if s.Subject == "" {
			return fmt.Errorf("%w: keyless signer missing subject", ErrInvalidSigner)
		}
	}

	return nil
}

// IsSSH returns true if this signer uses SSH key-based signing.
func (s *Signer) IsSSH() bool {
	return s.PublicKey != nil
}

// IsKeyless returns true if this signer uses keyless/OIDC-based signing.
func (s *Signer) IsKeyless() bool {
	return s.PublicKey == nil
}

// Matches checks if a EventSigner (from a signature) matches this trusted Signer.
// For SSH signers, compares fingerprints.
// For keyless signers, matches issuer exactly and subject as regex.
func (s *Signer) Matches(match internal.EventSigner) bool {
	if s.IsSSH() {
		if !match.IsSSH() {
			return false
		}

		return s.Fingerprint() == match.Fingerprint
	}

	if s.IsKeyless() {
		if !match.IsKeyless() {
			return false
		}

		if s.Issuer != match.Issuer {
			return false
		}

		// Subject can be a regex pattern
		subjectPattern, err := regexp.Compile("^" + s.Subject + "$")
		if err != nil {
			// If the pattern is invalid, fall back to exact match
			return s.Subject == match.Subject
		}

		return subjectPattern.MatchString(match.Subject)
	}

	return false
}

// Fingerprint computes the SSH fingerprint for this signer's public key.
// Returns empty string if the signer is not SSH-based or the key is invalid.
func (s *Signer) Fingerprint() string {
	if !s.IsSSH() {
		return ""
	}

	return s.PublicKey.Fingerprint()
}
