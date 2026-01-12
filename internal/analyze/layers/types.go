package layers

import (
	"os"
)

// Assessment represents a single finding from layer analysis.
type Assessment struct {
	Code       string // Checkpoint code (e.g., "CIS-DI-0008").
	Title      string // Human-readable title.
	Level      Level  // Severity level.
	Message    string // Detailed description.
	LayerIndex int    // Which layer contained the issue (0-based).
	Filename   string // File path within the layer.
}

// Level represents the severity of a finding.
type Level int

// Level constants for assessment severity.
const (
	LevelPass Level = iota + 1
	LevelIgnore
	LevelSkip
	LevelInfo
	LevelWarn
	LevelFatal
)

// String returns the string representation of the level.
func (l Level) String() string {
	switch l {
	case LevelPass:
		return "PASS"
	case LevelIgnore:
		return "IGNORE"
	case LevelSkip:
		return "SKIP"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Checkpoint codes for layer-based checks.
const (
	// CIS Docker Image benchmarks.
	CodeCheckSuidGuid   = "CIS-DI-0008"
	CodeAvoidCredential = "CIS-DI-0010" //nolint:gosec // Checkpoint code, not a credential.

	// Dockle layer checks.
	CodeAvoidEmptyPassword      = "DKL-LI-0001"
	CodeAvoidDuplicateUserGroup = "DKL-LI-0002"
	CodeInfoDeletableFiles      = "DKL-LI-0003"
)

// DefaultLevels maps checkpoint codes to their default severity levels.
//
//nolint:gochecknoglobals // Read-only lookup table.
var DefaultLevels = map[string]Level{
	CodeCheckSuidGuid:           LevelInfo,
	CodeAvoidCredential:         LevelFatal,
	CodeAvoidEmptyPassword:      LevelFatal,
	CodeAvoidDuplicateUserGroup: LevelFatal,
	CodeInfoDeletableFiles:      LevelInfo,
}

// Titles maps checkpoint codes to their human-readable descriptions.
//
//nolint:gochecknoglobals // Read-only lookup table.
var Titles = map[string]string{
	CodeCheckSuidGuid:           "Confirm safety of setuid/setgid files",
	CodeAvoidCredential:         "Do not store credentials in image",
	CodeAvoidEmptyPassword:      "Avoid empty password",
	CodeAvoidDuplicateUserGroup: "Be unique UID/GID",
	CodeInfoDeletableFiles:      "Only put necessary files",
}

// Options configures scanner behavior.
type Options struct {
	// AdditionalCredentialFiles are extra filenames to flag as credentials.
	AdditionalCredentialFiles []string

	// AdditionalCredentialExtensions are extra extensions to flag as credentials.
	AdditionalCredentialExtensions []string
}

// FileEntry represents a file encountered during layer scanning.
type FileEntry struct {
	Path    string
	Mode    os.FileMode
	Content []byte // Only populated for files that need content analysis.
}
