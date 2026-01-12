# QIX: Quark Index Architecture

## Problem

OCI registries are content-addressed blob stores with mutable tag pointers. They cannot answer: "what is the complete, current, non-downgradable set of attestations for artifact X?"

Existing solutions (Rekor, Sigsum) provide append-only transparency logs but no state index. They answer "this signature exists" not "what's the current trusted state."

## Solution

Three components:

1. **Registry** — dumb content-addressed storage (image indexes, attestations, all by digest)
2. **QIX (Quark Index)** — OCI index bundling an image index + all its attestations
3. **Git tlog** — signed state transitions tracking current valid QIX for each artifact

## QIX Structure

```
QIX (OCI Index)
├── image index (digest)
├── attestation manifest A
├── attestation manifest B
└── ...
```

Attestations are standard OCI single-layer manifests. The `subject` field identifies what each attestation applies to (image index or per-platform manifest).

### Per-platform vs index-level attestations

| Attestation Type | Level |
|------------------|-------|
| SBOM | Per-platform manifest |
| Vulnerability scan | Per-platform manifest |
| Build provenance | Per-platform manifest |
| Policy approval | Image index |
| Stage approval | Image index |

All attestations live flat in the QIX. Consumers filter by `subject` field.

## Git Transparency Log

A git repository serving as the source of truth for artifact state.

### Commit structure

Each commit:
- **Message**: structured data identifying artifact, QIX digest, timestamp
- **Signature**: GPG/SSH signature by authorized key

Example commit message:
```json
{
  "artifact": "registry.com/foo/bar",
  "qix_digest": "sha256:ABC123...",
  "timestamp": "2025-01-05T10:30:00Z"
}
```

### Why git?

- Every org already has secured git infrastructure
- No new services to deploy
- Native signing support (`git verify-commit`)
- Replication to multiple remotes = tamper evidence
- Teams already know how to operate it

### Security model

- Branch protection (no force push)
- Push to multiple independent remotes
- Divergence = detected tampering

This is tamper-evident, not tamper-proof. Sufficient for most supply chain threat models.

## Promotion Workflow

Artifacts progress through stages. Each stage:
1. Retrieves previous QIX
2. Adds stage-specific attestations
3. Adds stage-approval attestation
4. Signs new QIX
5. Commits to tlog

### Example progression

**Dev stage (Alice):**
```
QIX-dev
├── image index: sha256:IMG
├── SBOM attestation
└── dev-approval attestation (signed: alice)
```

**QA stage (Bob):**
```
QIX-qa
├── image index: sha256:IMG
├── SBOM attestation
├── dev-approval attestation
├── test-results attestation
└── qa-approval attestation (signed: bob)
```

**Security stage (Carol):**
```
QIX-security
├── image index: sha256:IMG
├── SBOM attestation
├── dev-approval attestation
├── test-results attestation
├── qa-approval attestation
├── scan-results attestation
└── security-approval attestation (signed: carol)
```

### Chain of custody

The image index digest is the anchor. Each QIX references the same `sha256:IMG`. Approval attestations provide explicit certification that each stage passed.

## Approval Attestation Format

```json
{
  "predicateType": "quark.dev/approval/v1",
  "predicate": {
    "stage": "qa",
    "result": "pass",
    "timestamp": "2025-01-05T10:30:00Z"
  }
}
```

## Admission Controller Flow

1. Receive deployment request for `foo/bar`
2. Query git tlog for latest QIX signed by security team
3. Retrieve QIX by digest from registry
4. Verify QIX signature matches tlog entry
5. Verify required approval attestations present (dev, qa, security)
6. Extract image index digest from QIX
7. Authorize runtime to pull image by digest only

**Critical:** Runtime pulls by digest, never by tag.

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Tamper evidence | Git history + signatures + multi-remote replication |
| No attestation removal | QIX digest changes if content changes |
| No downgrade | Tlog provides ordering; policy rejects older entries |
| Chain of custody | Approval attestations + immutable image index anchor |
| Non-repudiation | Commit signatures in tlog |

## Out of Scope

- Key management / PKI (use whatever: step-ca, Fulcio, HSM)
- Git infrastructure security (assumed secured by org)
- Registry security (trust only digests, not tags)