// Package layers provides security analysis of OCI image layer contents.
//
// This package scans layer tar streams for security issues including:
//   - Credential files (SSH keys, .env files, password files)
//   - Empty passwords in /etc/shadow
//   - Duplicate UID/GID in /etc/passwd and /etc/group
//   - SUID/SGID permission bits
//
// Each layer is analyzed independently to detect credentials that may have
// been added in one layer and removed in a subsequent layer - the credential
// still exists in the earlier layer blob and can be extracted.
//
// This package provides two implementations:
//   - Native: Pure Go implementation with no external dependencies
//   - Wrapper: Uses dockle's assessors directly
package layers
