package sync

import "github.com/farcloser/quark/sdk/platform"

// Options configures sync behavior.
type Options struct {
	Platforms []*platform.Platform
}
