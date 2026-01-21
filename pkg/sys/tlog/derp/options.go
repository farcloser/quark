package derp

import (
	"github.com/farcloser/quark/pkg/core/git"
)

// config holds the configuration for a Log instance.
type config struct {
	author          git.Author
	remote          string
	hostFingerprint string
	withSSHConfig   bool
}

// Option configures a Log instance.
type Option func(*config)

// WithAuthor sets the commit author and signing key.
// The author's Key field is used for both commit signing and SSH transport authentication.
func WithAuthor(author git.Author) Option {
	return func(cfg *config) {
		cfg.author = author
	}
}

// WithRemote sets the remote name (default: "origin").
func WithRemote(name string) Option {
	return func(cfg *config) {
		cfg.remote = name
	}
}

// WithHostFingerprint sets the SSH host key fingerprint for verification.
// If set, this overrides ~/.ssh/known_hosts verification.
// The fingerprint should be in SHA256 format (e.g., "SHA256:...").
func WithHostFingerprint(fingerprint string) Option {
	return func(cfg *config) {
		cfg.hostFingerprint = fingerprint
	}
}

// WithoutSSHConfig disables ~/.ssh/config resolution for remote operations.
// By default, SSH config is used for User, Hostname, Port, and IdentityFile resolution.
func WithoutSSHConfig() Option {
	return func(cfg *config) {
		cfg.withSSHConfig = false
	}
}

func defaultConfig() *config {
	return &config{
		remote: "origin",
		author: git.Author{
			Name:  "tlog",
			Email: "tlog@localhost",
		},
		withSSHConfig: true,
	}
}

func applyOptions(opts []Option) *config {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}

// buildAuth constructs SSHAuth for the given endpoint using config settings.
func (c *config) buildAuth(endpoint string) *git.SSHAuth {
	if c.author.Key == nil {
		return nil
	}

	return git.NewSSHAuth(endpoint, c.hostFingerprint, c.author.Key, c.withSSHConfig)
}
