package kit

import (
	"github.com/farcloser/quark/kit/defaults"
)

// Shutdown executes all registered shutdown handlers.
// Call via defer in main() to ensure cleanup on normal exit.
// Safe to call multiple times; handlers only execute once.
func Shutdown() {
	defaults.RunShutdownHandlers()
}
