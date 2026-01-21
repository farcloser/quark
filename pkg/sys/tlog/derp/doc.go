// Package tlog provides a git-based transparency log for cryptographically
// verifiable event tracking.
//
// The transparency log uses signed git commits to create an append-only,
// tamper-evident record of events. Each entry is stored as a signed empty
// commit with JSON metadata in the commit message.
//
// # Entry Types
//
// The log supports six entry types:
//
//   - genesis: The first entry establishing the initial admin
//   - trust_admin: Grants admin privileges to a signer
//   - trust_signer: Grants signer privileges (can sign events)
//   - revoke_admin: Revokes admin privileges from a signer
//   - revoke_signer: Revokes signer privileges from a signer
//   - event: Records a signed event with subject and identifier
//
// # Trust Model
//
// The log has two orthogonal privilege levels:
//
//   - Admin: Can manage trust (trust_admin, trust_signer, revoke_admin, revoke_signer)
//   - Signer: Can sign events
//
// A signer can have both, one, or neither privilege. Genesis establishes a
// single admin who can then grant privileges to others.
//
// # Signer Types
//
// Two signing mechanisms are supported:
//
//   - SSH: Traditional SSH key signing using ed25519 or RSA keys
//   - Keyless: OIDC-based signing via Fulcio (e.g., GitHub Actions, Google)
//
// # Verification
//
// The log supports explicit verification through VerifySigner() and VerifyAdmin().
// Operations that depend on verified state will fail with ErrNotVerified
// if called before verification completes successfully.
//
// # Example Usage
//
//	log, err := tlog.Open(repo, tlog.WithRef("refs/tlog/events"))
//	if err != nil {
//	    return err
//	}
//
//	latest, err := log.Latest("ghcr.io/myorg/myapp")
//	if err != nil {
//	    return err
//	}
package derp
