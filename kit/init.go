package kit

import (
	"context"

	"github.com/farcloser/quark/kit/defaults"
)

// Initialize sets up kit and returns a context that is cancelled on SIGINT/SIGTERM.
// A background goroutine listens for signals and triggers graceful shutdown.
// Use the returned context throughout your application for cancellation propagation.
func Initialize(parent context.Context) context.Context {
	defaults.SetDefaultsForLogger(parent)
	defaults.SetDefaultsForNetwork()
	defaults.SetDefaultsForSecrets()

	return defaults.SetDefaultsForShutdown(parent)
}
