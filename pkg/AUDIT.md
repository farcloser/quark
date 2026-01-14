# Quark pkg/ Audit Report

Date: 2026-01-14 (consolidated)

## Executive Summary

Overall assessment: **Good quality codebase** with modern security practices, clear package structure, and solid test coverage in core areas.

**Key Issues:**
- 1 Medium severity (TOCTOU race in SFTP upload, awaiting pkg/sftp v2)

**Security Posture**: Strong. TLS 1.3 with post-quantum crypto, hardened SSH defaults, content-addressed storage with digest verification.

---

## 1. Positive Security Findings

### TLS Configuration (pkg/core/network/http.go)
- TLS 1.3 minimum enforced
- Post-quantum hybrid key exchange (X25519MLKEM768) as preferred
- X25519 fallback for compatibility
- ResponseHeaderTimeout (30s) prevents slow-header attacks
- **Threat mitigated**: Store-now-decrypt-later attacks, slowloris-style header stalling

### SSH Configuration (pkg/core/network/ssh.go)
- Curve25519 key exchanges only
- AEAD ciphers only (ChaCha20-Poly1305, AES-GCM) - no CBC mode
- Encrypt-then-MAC only
- Ed25519 host keys only
- **Threat mitigated**: MITM attacks via weak cipher negotiation, padding oracle attacks

### SSH Key Handling (pkg/core/sshprime/auth.go)
- Refuses to use unencrypted private keys from disk
- **Threat mitigated**: Key theft from compromised systems

### Content-Addressed Storage (pkg/dev/store/cache.go)
- SHA256 digest verification on write completion
- Hash mismatch causes write rejection
- No path traversal possible (digest is hex-encoded hash)
- **Threat mitigated**: Cache poisoning via TOCTOU or corrupted downloads

### Archive Extraction Security (pkg/dev/tools/installer_http.go)
- Path traversal protection via `isSubPath()` validation
- Symlink attack prevention (both extractors skip symlinks)
- Decompression bomb protection (2GB budget limit for full extraction)
- Atomic installation (extract to temp, then rename)
- Concurrent installation race handling (graceful on competing processes)
- Archive permissions stripped to private (only execute bit preserved)
- **Comprehensive test coverage** for security-critical extraction code

### SSH Signature Parsing (pkg/core/git/consts.go)
- Maximum 64KB field length for SSH signatures
- **Threat mitigated**: Resource exhaustion via maliciously crafted signatures

### Additional Security Controls
- Path validation (ValidatePath, ValidatePathComponent)
- Socket path length validation
- File permissions (private directories/files use 0700/0600)
- Lock file handling (no TOCTOU vulnerabilities in locking protocol)
- Reference-counted file store (Locker provides cross-process serialization)

---

## 2. Medium Priority Issues

### M1: TOCTOU Race in SFTP File Upload

**File:** `core/sshprime/client.go:287-304`
**Status:** Known issue, FIXME in code awaiting pkg/sftp v2.

File created with default umask, then chmod called. Small race window exists.

---

## 3. Low Priority Issues

| Location | Issue |
|----------|-------|
| `dev/store/stores.go:28-53` | Global singletons cannot be reset for testing |

---

## 4. Test Coverage

| Package | Coverage | Assessment |
|---------|----------|------------|
| pkg/core/filesystem | 44.4% | Acceptable |
| pkg/core/network | 90.3% | Excellent |
| pkg/core/git | 69.6% | Acceptable |
| pkg/core/serializable | 100.0% | Excellent |
| pkg/core/sshprime | 75.9% | Good |
| pkg/core/trust | 85.0% | Excellent |
| pkg/dev/format | 98.6% | Excellent |
| pkg/dev/store | 56.6% | Good |
| pkg/dev/tools | 49.8% | Good |
| pkg/sys/policy | 100.0% | Excellent |
| pkg/version | 100.0% | Excellent |

---

## 5. Summary

| Severity | Count |
|----------|-------|
| High     | 0     |
| Medium   | 1     |
| Low      | 1     |

---

## Files Reviewed

### pkg/core/
- digest/*.go, *_test.go
- filesystem/*.go, *_test.go
- git/*.go, *_test.go
- network/*.go, *_test.go
- serializable/*.go, *_test.go
- sshprime/*.go, *_test.go
- trust/*.go, *_test.go

### pkg/dev/
- dag/*.go, *_test.go
- format/*.go, *_test.go, sarif/*.go
- network/*.go, *_test.go
- ssh/*.go, *_test.go
- store/*.go, *_test.go
- tunnel/*.go, *_test.go

### pkg/sys/
- policy/*.go, *_test.go
- resource/*.go, *_test.go
- secrets/*.go, *_test.go
- tools/*.go, *_test.go

### pkg/fault/
- errors.go, *_test.go, doc.go

### pkg/version/
- version.go, *_test.go, doc.go
