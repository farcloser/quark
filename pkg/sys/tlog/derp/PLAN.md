# tlog Implementation Plan

## Scope

Implement the tlog (transparency log) primitives that:
1. Write entries to git (signed empty commits with JSON messages)
2. Retrieve entries from git (iterate, query by artifact)
3. Verify chain integrity (signature validation, trust chain replay)

**Out of scope:** CLI tool, QIX integration, admission controller. This is the library layer only.

---

## API Design

### Primary Types

```go
// Log is the main entry point for tlog operations.
type Log struct {
    repo   *git.Repo
    author git.Author
    signer CommitSigner  // abstraction over SSH/gitsign
}

// Entry is the common interface for all tlog entries.
type Entry interface {
    Type() EntryType
    Timestamp() time.Time
}

// CommitSigner abstracts over signing methods (SSH keys, gitsign/Fulcio).
type CommitSigner interface {
    // Sign creates a signed commit. Implementation handles the signing mechanism.
    Sign(repo *git.Repo, message string, author *git.Author, when time.Time) (hash string, err error)
}

// Signer identifies a trusted signer in the log.
// Supports both key-based (SSH) and keyless (Fulcio/OIDC) identities.
type Signer struct {
    ID string `json:"id"`

    // Key-based signing (SSH) - set these fields
    KeyType   string `json:"key_type,omitempty"`    // e.g., "ssh-ed25519"
    PublicKey string `json:"public_key,omitempty"`  // base64-encoded

    // Keyless signing (Fulcio/OIDC) - set these fields
    // Reuses types.KeylessSignerInfo model from sys/signature
    Issuer  string `json:"issuer,omitempty"`   // e.g., "https://accounts.google.com"
    Subject string `json:"subject,omitempty"`  // e.g., "alice@example.com" or regex pattern
}

// SignerMatch represents a verified signer identity from a commit.
// Returned by verification, used to match against trusted Signer entries.
type SignerMatch struct {
    // For SSH signatures
    Fingerprint string  // SHA256:... (set if SSH)

    // For keyless/Fulcio signatures (matches types.KeylessSignerInfo)
    Issuer  string  // set if keyless
    Subject string  // set if keyless
}
```

### Entry Types

```go
type EntryType string

const (
    EntryTypeGenesis      EntryType = "genesis"
    EntryTypeRelease      EntryType = "release"
    EntryTypeAddSigner    EntryType = "add_signer"
    EntryTypeRevokeSigner EntryType = "revoke_signer"
)

// GenesisEntry establishes the trust anchor (first commit).
type GenesisEntry struct {
    Version        int      `json:"version"`
    TrustedSigners []Signer `json:"trusted_signers"`
}

// ReleaseEntry points to a QIX for an artifact.
type ReleaseEntry struct {
    Artifact  string    `json:"artifact"`   // e.g., "ghcr.io/myorg/myapp"
    QIX       string    `json:"qix"`        // e.g., "sha256:abc123..."
    Timestamp time.Time `json:"ts"`
}

// AddSignerEntry expands the trusted signer set.
type AddSignerEntry struct {
    Timestamp time.Time `json:"timestamp"`
    Signer    Signer    `json:"signer"`
}

// RevokeSignerEntry removes a signer (handles key compromise).
type RevokeSignerEntry struct {
    Timestamp          time.Time `json:"timestamp"`
    SignerID           string    `json:"signer_id"`
    Reason             string    `json:"reason"`
    EntriesValidBefore time.Time `json:"entries_valid_before"`
}
```

### Core Operations

```go
// --- Initialization ---

// Open opens an existing tlog repository.
func Open(path string, opts ...Option) (*Log, error)

// Clone clones a remote tlog repository.
func Clone(ctx context.Context, url, path string, opts ...Option) (*Log, error)

// Init creates a new tlog with a genesis commit.
func Init(path string, genesis *GenesisEntry, opts ...Option) (*Log, error)

// --- Writing ---

// Release adds a release entry for an artifact.
// Returns the commit hash.
func (l *Log) Release(ctx context.Context, artifact, qix string) (string, error)

// AddSigner adds a new trusted signer.
func (l *Log) AddSigner(ctx context.Context, signer Signer) (string, error)

// RevokeSigner revokes a signer (e.g., key compromise).
func (l *Log) RevokeSigner(ctx context.Context, signerID, reason string, validBefore time.Time) (string, error)

// --- Syncing ---

// Fetch fetches from remote (updates local state).
func (l *Log) Fetch(ctx context.Context) error

// Push pushes to remote (with retry on conflict).
// Returns ErrNonFastForward if rebase needed.
func (l *Log) Push(ctx context.Context) error

// Sync fetches and pushes, handling conflicts with retry.
// maxRetries controls how many times to retry on conflict.
func (l *Log) Sync(ctx context.Context, maxRetries int) error

// --- Reading ---

// Head returns the current HEAD commit hash.
func (l *Log) Head() (string, error)

// Latest returns the latest release entry for an artifact.
// Returns ErrNotFound if no releases exist for the artifact.
func (l *Log) Latest(artifact string) (*ReleaseEntry, string, error)

// Entries returns an iterator over all entries (newest first).
func (l *Log) Entries() (*EntryIter, error)

// EntriesFor returns an iterator over entries for a specific artifact.
func (l *Log) EntriesFor(artifact string) (*EntryIter, error)

// --- Verification ---

// Verify verifies the entire chain from genesis.
// Returns the computed trusted signer set at HEAD.
// Returns error if any signature is invalid or from untrusted signer.
func (l *Log) Verify() ([]Signer, error)

// VerifyFrom verifies the chain from a known-good commit to HEAD.
// Used for incremental verification (avoid full replay every time).
// knownSigners is the trusted signer set at fromCommit.
func (l *Log) VerifyFrom(fromCommit string, knownSigners []Signer) ([]Signer, error)

// IsAncestor returns true if ancestor is an ancestor of HEAD.
// Used to detect history rewrites.
func (l *Log) IsAncestor(ancestor string) (bool, error)

// TrustedSigners returns the current trusted signer set.
// Requires Verify() to have been called first.
func (l *Log) TrustedSigners() []Signer
```

### Options

```go
type Option func(*config)

// WithAuthor sets the commit author.
func WithAuthor(name, email string) Option

// WithSSHSigner sets an SSH signer for creating commits.
func WithSSHSigner(signer ssh.Signer) Option

// WithGitsigner sets a gitsign/Fulcio signer for creating commits.
// (Future: when gitsign support is added to core/git)
func WithGitsigner(/* TBD */) Option

// WithSSHAuth sets SSH authentication for remote operations.
func WithSSHAuth(auth gitssh.AuthMethod) Option

// WithRemote sets the remote name (default: "origin").
func WithRemote(name string) Option

// WithSigstoreRoot sets the sigstore trust root for Fulcio verification.
// If not set, uses signature.Root (global default).
func WithSigstoreRoot(root *types.Trusted) Option
```

---

## Signer Identity Model

### Two signing modes

| Mode | Identity | Commit Signature | Verification |
|------|----------|------------------|--------------|
| **SSH** | Key fingerprint | SSH signature (git 2.34+) | `core/git.GetCommitSigner()` |
| **Keyless** | OIDC (issuer + subject) | X.509/gitsign | Fulcio cert chain + Rekor |

### Signer matching logic

```go
// matches checks if a SignerMatch (from commit) matches a Signer (from trust list).
func (s *Signer) matches(m *SignerMatch) bool {
    // SSH: match by fingerprint
    if s.PublicKey != "" && m.Fingerprint != "" {
        return fingerprintOf(s.PublicKey) == m.Fingerprint
    }

    // Keyless: match by issuer + subject pattern
    if s.Issuer != "" && m.Issuer != "" {
        if s.Issuer != m.Issuer {
            return false
        }
        // Subject can be exact match or regex pattern
        return matchSubject(s.Subject, m.Subject)
    }

    return false
}
```

### Reusing sys/signature infrastructure

- **`types.KeylessSignerInfo`** - Same model for OIDC identity (Issuer, Subject)
- **`signature.Root`** - Global Rekor trust root for Fulcio verification
- **Verification pattern** - `Verify() → signer info` mirrors OCI signature verification

---

## File Structure

```
pkg/sys/tlog/
├── doc.go           # Package documentation
├── errors.go        # Error definitions
├── signer.go        # Signer type + matching logic
├── entry.go         # Entry types + JSON serialization
├── log.go           # Log struct + core operations
├── verify.go        # Chain verification logic
├── options.go       # Option pattern
├── ssh.go           # SSH CommitSigner implementation
├── log_test.go      # Tests
└── verify_test.go   # Verification tests
```

---

## Implementation Order

### Phase 1: Entry Types (`entry.go`, `errors.go`, `signer.go`)
1. Define `EntryType` enum
2. Define `Signer` struct with SSH + keyless fields
3. Implement `Signer.matches(SignerMatch)` logic
4. Define all entry structs with JSON tags
5. Implement `parseEntry(json []byte) (Entry, error)`
6. Implement `marshalEntry(entry Entry) ([]byte, error)`
7. Add validation for required fields

### Phase 2: Log Core (`log.go`, `options.go`, `ssh.go`)
1. Define `CommitSigner` interface
2. Implement `sshCommitSigner` using `core/git.CreateEmptyCommit`
3. Define `Log` struct wrapping `*git.Repo`
4. Implement `Open`, `Clone`, `Init`
5. Implement `Head`, `Fetch`, `Push`
6. Implement `Release`, `AddSigner`, `RevokeSigner`
7. Implement `Sync` with retry logic

### Phase 3: Reading (`log.go` continued)
1. Implement `Entries()` iterator
2. Implement `EntriesFor(artifact)` filtered iterator
3. Implement `Latest(artifact)`

### Phase 4: Verification (`verify.go`)
1. Define `SignerMatch` struct
2. Implement `extractSignerMatch(commit)` - SSH path via `core/git.GetCommitSigner`
3. Implement full chain replay from genesis
4. Track trusted signer set through add/revoke entries
5. Implement `VerifyFrom` for incremental verification
6. Implement history rewrite detection via `IsAncestor`

### Phase 5: Tests
1. Unit tests for entry parsing/marshaling
2. Unit tests for signer matching (SSH fingerprint, OIDC patterns)
3. Integration tests with real git repos (temp dirs)
4. Verification tests with valid/invalid chains
5. Conflict resolution tests

### Future: Gitsign Support
When needed, add to `core/git`:
1. `GetCommitSignerKeyless(hash) (*types.KeylessSignerInfo, error)`
2. Parse X.509 signature from commit
3. Verify cert chain against Fulcio root
4. Check Rekor inclusion proof
5. Return issuer + subject

Then add `gitsignCommitSigner` implementing `CommitSigner`.

---

## Design Decisions

### 1. Build on core/git, not bypass it

The `core/git` package already provides:
- `CreateEmptyCommit` with SSH signing
- `GetCommitSigner` for SSH signature verification
- `Commits()` iterator
- `IsAncestor` for ancestry checks
- `Fetch`, `Push` with proper error handling

tlog wraps these, adding entry semantics.

### 2. CommitSigner abstraction

Rather than hardcoding SSH signing, we abstract via `CommitSigner` interface:
```go
type CommitSigner interface {
    Sign(repo *git.Repo, message string, author *git.Author, when time.Time) (hash string, err error)
}
```

This allows:
- `sshCommitSigner` - uses `core/git.CreateEmptyCommit` with `ssh.Signer`
- `gitsignCommitSigner` (future) - uses gitsign/Fulcio

### 3. Unified Signer type

Single `Signer` struct supports both modes:
```go
// SSH signer
Signer{ID: "bot", KeyType: "ssh-ed25519", PublicKey: "AAAA..."}

// Keyless/OIDC signer
Signer{ID: "alice", Issuer: "https://accounts.google.com", Subject: "alice@example.com"}

// Keyless with pattern
Signer{ID: "ci", Issuer: "https://token.actions.githubusercontent.com", Subject: "repo:myorg/.*"}
```

### 4. JSON message format

Entries are single-line compact JSON in commit messages:
```json
{"type":"release","artifact":"ghcr.io/foo/bar","qix":"sha256:...","ts":"2025-01-05T10:00:00Z"}
```

The `type` field enables parsing without knowing the type upfront.

### 5. Verification is explicit

Callers must call `Verify()` or `VerifyFrom()` explicitly. This avoids hidden expensive operations and makes the trust model clear:
- `Open()` does NOT verify
- `Latest()` does NOT verify
- You must verify before trusting results

### 6. Sync with retry

The `Sync` method handles the common case of concurrent writers:
```
1. Fetch latest
2. Create commit
3. Push
4. If conflict: fetch, reset to remote, recreate commit, retry
```

This works because tlog entries are independent - reordering doesn't change semantics.

---

## Error Handling

```go
var (
    // ErrNotInitialized indicates the log has no genesis commit.
    ErrNotInitialized = errors.New("tlog not initialized (no genesis)")

    // ErrInvalidGenesis indicates the first commit is not a valid genesis.
    ErrInvalidGenesis = errors.New("invalid genesis entry")

    // ErrInvalidEntry indicates a commit message is not valid JSON or unknown type.
    ErrInvalidEntry = errors.New("invalid tlog entry")

    // ErrUntrustedSigner indicates a commit was signed by an unknown key.
    ErrUntrustedSigner = errors.New("commit signed by untrusted signer")

    // ErrHistoryRewrite indicates the remote has rewritten history.
    ErrHistoryRewrite = errors.New("history rewrite detected")

    // ErrNoReleases indicates no release entries exist for the artifact.
    ErrNoReleases = errors.New("no releases for artifact")

    // ErrSyncConflict indicates max retries exceeded during sync.
    ErrSyncConflict = errors.New("sync conflict: max retries exceeded")

    // ErrSignerMismatch indicates signer has both SSH and keyless fields set.
    ErrSignerMismatch = errors.New("signer must be SSH or keyless, not both")
)
```

---

## Usage Examples

### Creating a new tlog (SSH)

```go
genesis := &tlog.GenesisEntry{
    Version: 1,
    TrustedSigners: []tlog.Signer{{
        ID:        "release-bot",
        KeyType:   "ssh-ed25519",
        PublicKey: base64.StdEncoding.EncodeToString(pubKey.Marshal()),
    }},
}

log, err := tlog.Init("/path/to/repo", genesis,
    tlog.WithAuthor("release-bot", "bot@example.com"),
    tlog.WithSSHSigner(sshSigner),
)
```

### Creating a new tlog (Keyless/OIDC)

```go
genesis := &tlog.GenesisEntry{
    Version: 1,
    TrustedSigners: []tlog.Signer{
        {
            ID:      "ci-pipeline",
            Issuer:  "https://token.actions.githubusercontent.com",
            Subject: "repo:myorg/myapp:ref:refs/heads/main",
        },
        {
            ID:      "security-team",
            Issuer:  "https://accounts.google.com",
            Subject: ".*@security\\.example\\.com",  // regex pattern
        },
    },
}

log, err := tlog.Init("/path/to/repo", genesis,
    tlog.WithAuthor("ci", "ci@example.com"),
    tlog.WithGitsigner(/* future */),
)
```

### Adding a release

```go
log, _ := tlog.Open("/path/to/repo",
    tlog.WithAuthor("release-bot", "bot@example.com"),
    tlog.WithSSHSigner(sshSigner),
    tlog.WithSSHAuth(sshAuth),
)

hash, err := log.Release(ctx, "ghcr.io/myorg/myapp", "sha256:abc123...")
if err != nil {
    return err
}

if err := log.Sync(ctx, 3); err != nil {
    return fmt.Errorf("failed to push release: %w", err)
}
```

### Verifying and querying

```go
log, _ := tlog.Open("/path/to/repo", tlog.WithSSHAuth(sshAuth))

// Fetch latest from remote
if err := log.Fetch(ctx); err != nil {
    return err
}

// Verify the chain (required before trusting results)
trustedSigners, err := log.Verify()
if err != nil {
    return fmt.Errorf("verification failed: %w", err)
}

// Now safe to query
release, commitHash, err := log.Latest("ghcr.io/myorg/myapp")
if err != nil {
    return err
}

fmt.Printf("Current QIX: %s (commit: %s)\n", release.QIX, commitHash)
```

### Incremental verification

```go
// Load last known state
lastHead := loadLastVerifiedHead()
lastSigners := loadLastVerifiedSigners()

// Fetch and verify only new commits
if err := log.Fetch(ctx); err != nil {
    return err
}

// Check for history rewrite
if ok, _ := log.IsAncestor(lastHead); !ok {
    return fmt.Errorf("history rewrite detected!")
}

// Verify only new commits
newSigners, err := log.VerifyFrom(lastHead, lastSigners)
if err != nil {
    return err
}

// Save new state
saveLastVerifiedHead(log.Head())
saveLastVerifiedSigners(newSigners)
```

---

## Open Questions for Review

1. **Remote name**: Should we support multiple remotes for mirroring, or keep it simple with single "origin"?

2. **Cache/state persistence**: Should the Log struct handle caching verified state, or leave that to callers?

3. **Entry iterator direction**: Newest-first (current plan) or oldest-first (more natural for replay)?

4. **Revocation semantics**: Should `EntriesValidBefore` be mandatory or optional (revoke all entries from that signer)?

5. **Subject matching**: Exact string match, or regex? (Current plan: regex for flexibility, e.g., `.*@example.com`)
