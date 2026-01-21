package defaults

import (
	"github.com/farcloser/quark/pkg/core/network"
)

// SetDefaultsForNetwork configures http.DefaultTransport with secure defaults
// and wraps it with logging.
func SetDefaultsForNetwork() {
	network.SetDefaults()
}
