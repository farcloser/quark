package build

import "github.com/farcloser/quark/sdk/platform"

// Options configures build behavior.
type Options struct {
	// Platforms specifies target platforms for multi-platform builds.
	Platforms []*platform.Platform

	// Args are build arguments passed to docker build (--build-arg).
	Args map[string]string
}
