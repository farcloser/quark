// Package tools provides auto-installation for external tools (go install or plain http retrieval and extraction).
//
// # Installation Strategy
//
// Go tools are installed using `go install <import-path>@<commit-hash>` which provides:
// - Immutable pinning: commit hashes never change (unlike tags which can be moved)
// - Reproducible builds: same commit always produces same binary
// - Security: we control exact source code being compiled
//
// HTTP downloads require a digest for verification.
// (Possibly) archive extraction is then performed ensuring:
// - no path traversal is possible
// - no extraction DOS bomb is possible
// Note that we purposely do NOT extract symlinks.
//
// # Updating Tool Versions
//
// To update a tool:
// 1. Find the release on GitHub (e.g., github.com/aquasecurity/trivy/releases)
// 2. Get the commit hash for that release tag
// 3. Update the Version field in the Tool struct
// 4. Test with `go install <import-path>@<new-commit-hash>`
//
// Never use short commit hashes in production - always use at least 7 characters
// for collision resistance (Go will accept and expand them).
//
// # Security
// The installer tool does guarantee that:
// - the requested package matches the requested digest
// - extraction is performed safely
//
// However, if the source has been compromised and you use the compromised digest, the tool does not protect you.
// It is your responsibility to:
// - ensure the specific blobs pointed at by that specific digest are legit
// - run them with the appropriate amount of caution (sandbox execution, namespace, chroot, whatever)
package tools
