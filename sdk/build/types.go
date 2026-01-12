package build

import (
	"net/netip"

	"github.com/farcloser/quark/sdk/platform"
)

// Options configures build behavior.
type Options struct {
	// Platforms specifies target platforms for multi-platform builds.
	Platforms []*platform.Platform

	// Args are build arguments passed to docker build (--build-arg).
	Args map[string]string

	// Target specifies a target build stage (--target).
	// If empty, the final stage is built.
	Target string

	// ExtraHosts adds custom host-to-IP mappings for the build (--add-host).
	// Key is the hostname, value is the IP address.
	ExtraHosts map[string]netip.Addr

	// Secrets are build secrets passed to docker build (--secret).
	// Key is the secret ID (used in Dockerfile RUN --mount=type=secret,id=<ID>),
	// value is the secret content.
	Secrets map[string]string

	// NoLog suppresses build progress output (uses --progress quiet).
	// Errors are still shown.
	NoLog bool
}
