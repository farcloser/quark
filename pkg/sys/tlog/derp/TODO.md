# Git-Based Minimalistic Transparency Log (tlog)

A lightweight append-only ledger using git primitives (empty signed commits).

## Context: QIX Architecture

The tlog is one component of a larger supply chain architecture (see THOUGHTS.md):

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Registry (dumb)     QIX (signed bundle)      tlog (state)     │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │ blobs by     │    │ OCI Index:       │    │ Git commits: │  │
│  │ digest       │◄───│ - image index    │◄───│ artifact →   │  │
│  │              │    │ - attestations   │    │ qix digest   │  │
│  └──────────────┘    └──────────────────┘    └──────────────┘  │
│                              ▲                      ▲          │
│                              │                      │          │
│                         (signed OCI)          (signed commit)  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

Verification flow:
  1. Query tlog → get current QIX digest for artifact
  2. Fetch QIX from registry → verify QIX signature
  3. Extract attestations from QIX → verify each signature
  4. Policy check → required attestations present?
  5. Pull image BY DIGEST ONLY
```

**Separation of concerns:**

| Component | Answers | Trust |
|-----------|---------|-------|
| Registry | "Here's bytes for digest X" | Digests only, not tags |
| QIX | "Here's image + attestations as immutable bundle" | Signed OCI content |
| tlog | "This is the CURRENT valid QIX for artifact X" | Signed commits |

## Overview

Use git's commit chain as a transparency log:
- Each entry = signed empty commit with JSON message
- Commit chain = append-only ordering
- Signed commits = authentication
- No files, no complex infrastructure

```
commit C (HEAD)
├── parent: B
├── message: {"type":"release","artifact":"...","qix":"sha256:...","ts":"..."}
└── signature: <ssh/gpg>

commit B
├── parent: A
├── message: {"type":"release","artifact":"...","qix":"sha256:...","ts":"..."}
└── signature: <ssh/gpg>

commit A (genesis)
├── parent: null
├── message: {"type":"genesis","trusted_signers":[...]}
└── signature: <ssh/gpg>
```

---

## Design

### Entry Types

```json
// Genesis (first commit) - establishes trust anchor
{
  "type": "genesis",
  "version": 1,
  "trusted_signers": [
    {
      "id": "release-bot",
      "key_type": "ssh-ed25519",
      "public_key": "AAAA..."
    }
  ]
}

// Release entry - points to QIX (source of truth)
// Minimal by design: QIX contains all details (image digest, attestations, etc.)
// If tlog compromised, attacker can only do downgrade attacks, not forgery
{
  "type": "release",
  "artifact": "ghcr.io/myorg/myapp",
  "qix": "sha256:abc123...",
  "ts": "2025-01-05T09:15:00Z"
}

// Add signer - expand trust
{
  "type": "add_signer",
  "timestamp": "2025-01-05T10:00:00Z",
  "signer": {
    "id": "alice",
    "key_type": "ssh-ed25519",
    "public_key": "BBBB..."
  }
}

// Revoke signer - handle key compromise
{
  "type": "revoke_signer",
  "timestamp": "2025-01-05T11:00:00Z",
  "signer_id": "alice",
  "reason": "key compromised",
  "entries_valid_before": "2025-01-05T10:30:00Z"
}
```

### Commit Structure

- **Empty commits**: No tree changes, just message + signature
- **Message format**: Compact JSON (one line, no pretty-print)
- **Signature**: SSH key (`git -c gpg.format=ssh commit -S`)

### Conflict Resolution

Multiple writers may race. Handle via retry + rebase:

```
1. Fetch latest
2. Create signed commit
3. Push
4. If rejected (non-fast-forward):
   a. Fetch again
   b. Rebase (commit gets new hash)
   c. Re-sign
   d. Retry push
5. Max N retries with jitter
```

### Client Verification

Clients MUST verify:

1. **Append-only**: New HEAD must be descendant of last known HEAD
2. **Signatures**: Each commit signed by trusted signer (at that point in chain)
3. **Trust chain**: Replay from genesis, applying add/revoke operations

```
For each fetch:
  1. Check: is old_head ancestor of new_head? (no history rewrite)
  2. Replay commits from genesis:
     - Start with genesis trusted_signers
     - For each commit:
       - Verify signature against current trusted set
       - If add_signer: add to trusted set
       - If revoke_signer: remove from trusted set
  3. Store new_head locally
```

---

## Implementation Plan

### Phase 1: Core Library

- [ ] **Entry types** (`entry.go`)
  - [ ] Define Go structs for all entry types
  - [ ] JSON marshal/unmarshal
  - [ ] Validation (required fields, format)

- [ ] **Commit operations** (`commit.go`)
  - [ ] Create signed empty commit with message
  - [ ] Parse commit message to entry
  - [ ] Verify commit signature (SSH key)

- [ ] **Log operations** (`log.go`)
  - [ ] Initialize new log (create genesis)
  - [ ] Append entry (with retry/rebase on conflict)
  - [ ] Read all entries
  - [ ] Read entries by filter (type, artifact, time range)
  - [ ] Get latest entry for artifact

- [ ] **Verification** (`verify.go`)
  - [ ] Verify single commit signature
  - [ ] Verify full chain from genesis
  - [ ] Track trusted signers through add/revoke
  - [ ] Detect history rewrite (compare against last known head)

- [ ] **State tracking** (`state.go`)
  - [ ] Store/load last known HEAD
  - [ ] Store/load computed trusted signer set
  - [ ] Cache for performance (avoid full replay every time)

### Phase 2: Git Backend

- [ ] **Git operations** (`git.go`)
  - [ ] Use go-git or shell out to git CLI
  - [ ] Clone/fetch with depth control
  - [ ] Push with retry logic
  - [ ] Sign commits (SSH key integration)

- [ ] **Remote operations** (`remote.go`)
  - [ ] Fetch from remote
  - [ ] Push to remote
  - [ ] Handle authentication (SSH, token)

### Phase 3: CLI Tool

- [ ] `tlog init` - Create new log with genesis
- [ ] `tlog release <artifact> <qix>` - Add release entry
- [ ] `tlog add-signer` - Add trusted signer
- [ ] `tlog revoke-signer` - Revoke signer
- [ ] `tlog verify` - Verify log integrity
- [ ] `tlog latest <artifact>` - Get latest QIX digest for artifact
- [ ] `tlog history <artifact>` - List all entries for artifact
- [ ] `tlog check <artifact> <qix>` - Check if QIX is current (detect downgrade)

### Phase 4: Integration

- [ ] **QIX builder integration**
  - [ ] After building QIX, append release entry to tlog
  - [ ] Before trusting artifact, check tlog for current QIX

- [ ] **Policy/Admission controller**
  - [ ] Kyverno/OPA policy that checks tlog
  - [ ] Reject deployments where QIX digest != tlog latest for artifact

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Append-only | Git commit chain + client verification |
| Authenticated | Signed commits |
| Tamper-evident | Hash chain (each commit references parent) |
| Downgrade detection | Latest entry per artifact must match |
| Key compromise recovery | Revoke signer entries |
| Distributed hosting | Any git host (GitHub, GitLab, self-hosted) |

### Why Minimal Entries?

The tlog entry is intentionally minimal: `{artifact, qix, ts}`. No image digest, no tags, no attestation list.

**Security rationale:**

1. **QIX is source of truth** - All details (image digest, attestations, approvals) live in the QIX bundle, which is cryptographically signed OCI content.

2. **Defense in depth** - Even if tlog is compromised:
   - Attacker cannot forge QIX (signed OCI content)
   - Attacker can only point to a different (older) valid QIX
   - Result: downgrade attacks only, not forgery

3. **Blast radius limitation** - If tlog stored dereferenced fields:
   - Attacker could modify digest → point to malicious image
   - Attacker could modify attestations → bypass policy
   - Minimal data = minimal attack surface

4. **Single point of verification** - Clients verify:
   - tlog signature → "who said this QIX is current?"
   - QIX signature → "who bundled this content?"
   - Attestation signatures → "who made these claims?"
   - Clear chain of responsibility

## Trust Model

```
Trust Anchor: Genesis commit
    │
    ├── Contains initial trusted signers
    ├── Signed by bootstrap key (out-of-band trust)
    │
    ▼
Trust Evolution: Add/Revoke commits
    │
    ├── Existing trusted signer can add new signer
    ├── Existing trusted signer can revoke (including self)
    ├── Revocation specifies cutoff time for valid entries
    │
    ▼
Client Verification
    │
    ├── Replays chain from genesis
    ├── Builds trusted signer set dynamically
    ├── Verifies each commit against set at that point
    └── Rejects any commit from untrusted signer
```

## Limitations & Non-Goals

- **Not consensus**: Single authoritative chain, conflicts resolved by retry
- **Not Byzantine fault tolerant**: Trusts git host for availability
- **Not real-time**: Propagation depends on git fetch frequency
- **Not anonymous**: Signers are identified by public key

## Open Questions

1. **Multi-repo or single-repo**: One tlog per image, or one tlog for all images?
   - Single: Simpler, but grows large, all-or-nothing fetch
   - Multi: More repos to manage, but smaller, independent

2. **Signature format**: SSH keys, GPG, or gitsign (keyless)?
   - SSH: Simple, well-supported
   - GPG: Traditional, more complex
   - Gitsign: Keyless (OIDC), ties to identity provider

3. **Caching**: How to avoid full replay on every verification?
   - Store last verified HEAD + trusted signer set
   - Only replay new commits since last verification

4. **Mirroring**: Push to multiple remotes for redundancy?
   - Detect divergence across mirrors
   - Which mirror is authoritative?

---

## References

- Git commit signing: https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work
- SSH commit signing: https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#ssh-commit-signature-verification
- Sigstore gitsign: https://github.com/sigstore/gitsign
- Certificate Transparency (inspiration): https://certificate.transparency.dev/
- go-git library: https://github.com/go-git/go-git
