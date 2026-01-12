package layers

import (
	"path/filepath"
)

// Default suspicious filenames that may contain credentials.
//
//nolint:gochecknoglobals // Read-only configuration.
var defaultSuspiciousFiles = []string{
	"credentials.json",
	"credential.json",
	"credentials",
	"credential",
	"password.txt",
	"id_rsa",
	"id_dsa",
	"id_ecdsa",
	"id_ed25519",
	"secret_token.rb",
	"carrierwave.rb",
	"omniauth.rb",
	"settings.py",
	"database.yml",
	"credentials.xml",
	".env",
}

// Default suspicious file extensions.
//
//nolint:gochecknoglobals // Read-only configuration.
var defaultSuspiciousExtensions = []string{
	".secret",
	".ovpn",
	".private_key",
	".cscfg",
	".rdp",
	".mdf",
	".sdf",
	".bek",
	".tpm",
	".fve",
	".jks",
	".psafe3",
	".agilekeychain",
	".keychain",
	".pcap",
	".gnucache",
}

type credentialChecker struct {
	suspiciousFiles map[string]struct{}
	suspiciousExts  map[string]struct{}
}

func newCredentialChecker(opts Options) *credentialChecker {
	// Build suspicious files map.
	files := make(map[string]struct{})
	for _, f := range defaultSuspiciousFiles {
		files[f] = struct{}{}
	}

	for _, f := range opts.AdditionalCredentialFiles {
		files[f] = struct{}{}
	}

	// Build suspicious extensions map.
	exts := make(map[string]struct{})
	for _, e := range defaultSuspiciousExtensions {
		exts[e] = struct{}{}
	}

	for _, e := range opts.AdditionalCredentialExtensions {
		// Ensure extension starts with dot.
		if len(e) > 0 && e[0] != '.' {
			e = "." + e
		}

		exts[e] = struct{}{}
	}

	return &credentialChecker{
		suspiciousFiles: files,
		suspiciousExts:  exts,
	}
}

func (c *credentialChecker) check(entry FileEntry) *Assessment {
	basename := filepath.Base(entry.Path)

	// Check filename.
	if _, found := c.suspiciousFiles[basename]; found {
		return &Assessment{
			Code:     CodeAvoidCredential,
			Title:    Titles[CodeAvoidCredential],
			Level:    DefaultLevels[CodeAvoidCredential],
			Message:  "Suspicious filename found: " + entry.Path,
			Filename: entry.Path,
		}
	}

	// Check extension.
	ext := filepath.Ext(basename)
	if _, found := c.suspiciousExts[ext]; found {
		return &Assessment{
			Code:     CodeAvoidCredential,
			Title:    Titles[CodeAvoidCredential],
			Level:    DefaultLevels[CodeAvoidCredential],
			Message:  "Suspicious file extension found: " + entry.Path,
			Filename: entry.Path,
		}
	}

	return nil
}
