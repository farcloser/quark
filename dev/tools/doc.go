// Package tools provides auto-installation for external tools.
//
// # Installation Strategy
//
// Tools are installed using `go install <import-path>@<commit-hash>` which provides:
// - Immutable pinning: commit hashes never change (unlike tags which can be moved)
// - Reproducible builds: same commit always produces same binary
// - Security: we control exact source code being compiled
//
// # Version Pinning
//
// Commit hashes are used instead of version tags because:
// - Git tags can be deleted or moved to different commits
// - Commit SHA-256 hashes are cryptographically immutable
// - Go modules convert commit hashes to pseudo-versions automatically
//
// Example: go install github.com/aquasecurity/trivy/cmd/trivy@9aabfd2
// Go converts to: v0.0.0-20250205xxxxxx-9aabfd2 (pseudo-version)
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
package tools
