# Sigstore Integration Design

## Overview

Integrate sigstore-go for container image signature verification (and eventually signing).
Avoid cosign library due to heavy dependencies (~250 vs ~100 for sigstore-go).

## Source Image Verification

### Global Trust Configuration

```go
// At Plan level - add globally trusted signers
plan.TrustSigner(SignerIdentity{
    Subject: "ci@mycompany.com",
    Issuer:  "https://accounts.google.com",
})
```

### ImageOpts Extension

```go
type ImageOpts struct {
    // existing fields...

    // InsecureNoSignature bypasses signature verification (dangerous)
    InsecureNoSignature bool `json:"insecureNoSignature,omitempty"`

    // SignedBy overrides global trusted signers for this specific image
    // If set, signature must match one of these identities (global signers ignored)
    SignedBy []SignerIdentity `json:"signedBy,omitempty"`
}

type SignerIdentity struct {
    Subject string `json:"subject"` // email, OIDC subject, GitHub workflow path
    Issuer  string `json:"issuer"`  // https://accounts.google.com, https://token.actions.githubusercontent.com
}
```

### Verification Rules

1. `InsecureNoSignature: true` → skip verification (log warning)
2. `SignedBy` is set → must match one of `SignedBy` (global signers ignored)
3. `SignedBy` is empty → must match one of global `TrustSigner` identities
4. No `SignedBy` AND no global signers → error: no trust policy configured

### Verification Output

On success: returns the verified **digest** (not tag).

Tags are mutable; digests are what was actually signed. All operations (sync, scan, audit, versioncheck) should use the verified digest.

## Applies To

- **sync**: verify source before pulling/pushing
- **scan**: verify source before scanning
- **audit**: verify source before auditing
- **versioncheck**: verify source before checking versions

## Example Usage

```go
// Global trust
plan.TrustSigner(SignerIdentity{
    Subject: "ci@mycompany.com",
    Issuer:  "https://accounts.google.com",
})

// Per-image override
ImageOpts{
    Name:    "nginx",
    Domain:  "docker.io",
    Version: "1.25",
    SignedBy: []SignerIdentity{{
        Subject: "nginx-team@nginx.com",
        Issuer:  "https://accounts.google.com",
    }},
}

// Escape hatch (dangerous)
ImageOpts{
    Name:                "legacy-thing",
    InsecureNoSignature: true,
}
```

## Implementation Notes

### sigstore-go Plumbing Required

sigstore-go does not have built-in container image support. Need to build:

1. **Fetch signature from registry**: cosign convention is `sha256-<digest>.sig` tag
2. **Parse bundle from OCI layer**: simplesigning format, annotations contain certs/tlog entries
3. **Reconstruct SignedEntity**: for sigstore-go verification API
4. **Verify with policy**: match against expected SignerIdentity

Reference: `sigstore-go/examples/oci-image-verification/main.go` (~200 lines of plumbing)

### Transparency Log

Ignored for now. Can be added later for public audit trail via Rekor.

## Sync Operation Matrix

### Input Combinations & Outcomes

| Tag | Digest | InsecureNoSign | SignedBy/Global | Outcome |
|-----|--------|----------------|-----------------|---------|
| ✓ | ✓ | - | ✓ | **Pinned signed**: Verify signature on digest. If valid → sync by digest. If tag resolves to different digest → WARN (tag drift). |
| ✓ | ✓ | - | ✗ | ERROR: No trust policy configured. |
| ✓ | ✓ | ✓ | - | **Pinned insecure**: Sync digest directly. WARN (insecure). If tag resolves to different digest → WARN (tag drift). |
| ✓ | ✗ | - | ✓ | **Normal signed**: Resolve tag → get digest. Verify signature on digest. If valid → sync AND record verified digest (for future pinning). |
| ✓ | ✗ | - | ✗ | ERROR: No trust policy configured. |
| ✓ | ✗ | ✓ | - | **Insecure**: Resolve tag → sync. Log warning. No signature check. |
| ✗ | ✓ | - | ✓ | **Digest-only signed**: Verify signature on digest. If valid → sync. |
| ✗ | ✓ | - | ✗ | ERROR: No trust policy configured. |
| ✗ | ✓ | ✓ | - | **Digest-only insecure**: Sync digest directly. Log warning. |
| ✗ | ✗ | - | - | ERROR: Must specify at least tag or digest. |

### Key Principles

1. **Signature verification is mandatory by default** - must explicitly opt out with `InsecureNoSignature`
2. **Digest is the source of truth** - signatures are over digests, not tags
3. **Tag + Digest = drift detection** - if both specified, they must agree
4. **Verified digest is recorded** - enables future pinning and audit trail
5. **Warnings are loud** - `InsecureNoSignature` logs prominent warnings

### Signature Verification Failure Modes

| Failure | Outcome |
|---------|---------|
| No signature artifact found | ERROR: Image not signed |
| Signature invalid (crypto failure) | ERROR: Signature verification failed |
| Signer identity doesn't match policy | ERROR: Signer not trusted (got X, expected Y) |
| Signature is over different digest | ERROR: Signature digest mismatch |

### DX Considerations

1. **Clear error messages**: Always show what was expected vs what was found
2. **Actionable guidance**: "Add `InsecureNoSignature: true` to bypass (not recommended)"
3. **Progressive security**: Start with `InsecureNoSignature`, add signatures, then pin digests
4. **Manifest output**: After sync, output the verified digest for easy pinning

### Example Flows

**First-time sync (unsigned legacy image):**
```json
{
  "source": {
    "name": "oldimage",
    "domain": "docker.io",
    "version": "v1.0",
    "insecureNoSignature": true
  }
}
```
→ Syncs with warning. User should migrate to signed images.

**Normal signed image:**
```json
{
  "source": {
    "name": "myapp",
    "domain": "ghcr.io",
    "version": "v2.0"
  }
}
```
→ Resolves tag, verifies signature against global signers, syncs, outputs verified digest.

**Pinned + signed (production):**
```json
{
  "source": {
    "name": "myapp",
    "domain": "ghcr.io",
    "version": "v2.0",
    "digest": "sha256:abc123..."
  }
}
```
→ Verifies signature on digest, confirms tag still points to same digest (drift detection), syncs.

**Per-image signer override:**
```json
{
  "source": {
    "name": "nginx",
    "domain": "docker.io",
    "version": "1.25",
    "signedBy": [{"subject": "security@nginx.com", "issuer": "https://accounts.google.com"}]
  }
}
```
→ Verifies signature matches nginx's signer (ignores global signers).

## TODO

- [ ] Destination image signing (after sync push)
- [ ] Key-based signing (vs keyless/Fulcio)
- [ ] Transparency log integration (Rekor)
