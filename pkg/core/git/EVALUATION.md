# Go Git Library Evaluation

## Requirements for tlog

Based on TODO.md, we need:
- Create signed empty commits with JSON message
- Push to remote with retry/rebase
- Fetch commits from remote
- Parse commit messages
- Verify commit signatures (SSH keys)
- SSH-agent authentication for push/fetch

## Library Candidates

### 1. go-git (github.com/go-git/go-git/v5)

| Criteria | Assessment |
|----------|------------|
| **Stars** | 7.1k |
| **Contributors** | 295 |
| **License** | Apache-2.0 |
| **Last Release** | v5.16.4 (Nov 2025) |
| **Maintenance** | Active, backed by gitsight |
| **Adopters** | Gitea, Pulumi, Keybase |
| **Dependencies** | 57 imports |
| **Imported By** | 4,756 packages |
| **CGO** | No (pure Go) |

**Pros:**
- Pure Go, no native dependencies
- Mature, widely adopted
- Active maintenance
- SSH-agent support for transport (clone/fetch/push)
- Full git object model (commits, trees, blobs)
- Pluggable storage backends (filesystem, in-memory)
- GPG/OpenPGP commit signing supported

**Cons:**
- **NO SSH commit signing support** (only GPG)
- Heavyweight for our use case (we only need commits, not trees/blobs)
- 57 transitive dependencies

**SSH-agent support:**
```go
import "github.com/go-git/go-git/v5/plumbing/transport/ssh"

auth, err := ssh.NewSSHAgentAuth("git")
// Uses SSH_AUTH_SOCK to connect to running agent
```

**Signing status:**
- Has `Signer` interface for custom implementations
- Built-in support only for OpenPGP (`SignKey *openpgp.Entity`)
- SSH signing would require custom implementation

---

### 2. git2go (github.com/libgit2/git2go)

| Criteria | Assessment |
|----------|------------|
| **Stars** | 2,000 |
| **Contributors** | 99 |
| **License** | MIT |
| **Last Release** | v34.0.0 (Oct 2022) |
| **Maintenance** | Slow, last release 2+ years ago |
| **CGO** | **Yes, required** |

**Pros:**
- Wraps libgit2 (battle-tested C library)
- Full git feature parity

**Cons:**
- **Requires CGO** (C compiler, cmake, pkg-config)
- **Requires OpenSSL + libssh2 development packages**
- Cross-compilation nightmare
- Last release over 2 years old
- Manual memory management concerns leak through

**Verdict:** Not suitable. CGO is a dealbreaker for portability.

---

### 3. Shell out to git CLI

| Criteria | Assessment |
|----------|------------|
| **Dependencies** | External `git` binary |
| **Portability** | Requires git installed |
| **SSH-agent** | Native support |
| **SSH signing** | Native support (git 2.34+) |

**Pros:**
- Full feature parity
- SSH signing just works
- SSH-agent just works
- No library maintenance burden

**Cons:**
- External dependency
- Subprocess overhead
- Output parsing fragility
- Error handling complexity

**Implementation:**
```go
// Sign commit with SSH key
cmd := exec.Command("git", "-c", "gpg.format=ssh",
    "-c", "user.signingkey=~/.ssh/id_ed25519",
    "commit", "-S", "--allow-empty", "-m", message)
cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+os.Getenv("SSH_AUTH_SOCK"))
```

---

### 4. Build from scratch (minimal implementation)

**What we actually need for tlog:**
1. Create empty commit objects
2. Sign commits with SSH key
3. Push commits via SSH
4. Fetch commits via SSH
5. Parse commit messages and signatures
6. Verify SSH signatures

**Complexity assessment:**

| Component | Effort | Notes |
|-----------|--------|-------|
| Git object format | Low | Well-documented, simple binary format |
| Commit creation | Low | ~50 lines (tree hash, parent, author, message) |
| Pack protocol | Medium | Required for push/fetch over SSH |
| SSH transport | Medium | Can use golang.org/x/crypto/ssh |
| SSH signing | Medium | Git signature format documented |
| SSH verification | Medium | Parse signature, verify with public key |

**Reference:** [gogit 400-line implementation](https://benhoyt.com/writings/gogit/) shows basic operations are achievable.

**Estimated effort:** 1-2 weeks for core functionality.

**Risk:** Pack protocol negotiation is tricky. Edge cases in signature format.

---

## SSH Signing Deep Dive

Git SSH signatures use a specific format (since git 2.34):

```
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg...
-----END SSH SIGNATURE-----
```

The signature envelope contains:
- Magic bytes: `SSHSIG`
- Namespace: `git` (for commits)
- Hash algorithm
- Signature over the commit content

**Go implementation would need:**
```go
import "golang.org/x/crypto/ssh"

// Parse SSH signature armor
// Extract signature bytes
// Verify using ssh.PublicKey.Verify()
```

---

## Recommendation

### Option A: go-git + custom SSH signer (Recommended)

Use go-git for git operations, implement custom `Signer` for SSH signing.

**Pros:**
- Leverages mature library for complex parts (pack protocol, objects)
- Only need to implement SSH signing (~200-300 lines)
- SSH-agent already works for transport

**Cons:**
- Carries go-git's 57 dependencies
- Still need to understand git signature format

**Implementation sketch:**
```go
type SSHSigner struct {
    key ssh.Signer // from ssh-agent
}

func (s *SSHSigner) Sign(message io.Reader) ([]byte, error) {
    content, _ := io.ReadAll(message)
    sig, _ := s.key.Sign(rand.Reader, content)
    return formatGitSSHSignature(sig), nil
}
```

### Option B: Shell out to git

**Pros:**
- Zero implementation for signing
- Guaranteed compatibility

**Cons:**
- External dependency
- Not pure Go

### Option C: Minimal from-scratch implementation

**Pros:**
- Exactly what we need, nothing more
- Full control
- Minimal dependencies

**Cons:**
- 1-2 weeks effort
- Pack protocol complexity
- Edge cases

---

## Decision Matrix

| Factor | go-git + SSH | Shell to git | From scratch |
|--------|--------------|--------------|--------------|
| Development time | 2-3 days | 1 day | 1-2 weeks |
| Dependencies | 57 | 1 (git binary) | ~5 |
| Maintenance | Low | Low | Medium |
| Portability | Excellent | Requires git | Excellent |
| Risk | Low | Low | Medium |

---

## Next Steps

1. **Prototype go-git + custom SSH signer** - verify `Signer` interface works for our use case
2. **Test SSH-agent integration** - confirm `NewSSHAgentAuth` works on macOS/Linux
3. **Document fallback** - shell to git if custom signer proves too complex

---

## References

- [go-git GitHub](https://github.com/go-git/go-git)
- [go-git pkg.go.dev](https://pkg.go.dev/github.com/go-git/go-git/v5)
- [go-git SSH transport](https://pkg.go.dev/github.com/go-git/go-git/v5/plumbing/transport/ssh)
- [git2go GitHub](https://github.com/libgit2/git2go)
- [gogit minimal implementation](https://benhoyt.com/writings/gogit/)
- [Git SSH signature format](https://git-scm.com/docs/gitformat-signature)
- [go-git commit signature verification](https://darkowlzz.github.io/post/git-commit-signature-verification/)
