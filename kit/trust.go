package kit

import (
	"crypto/x509"
	"net/http"
	"sync"

	"github.com/farcloser/quark/dev/network"
)

//nolint:gochecknoglobals // Singleton pattern: global cert pool modified via TrustRoot, used by all HTTP clients.
var (
	poolMu   sync.Mutex
	rootPool *x509.CertPool
)

// TrustRoot adds a root CA certificate to the system pool and configures
// both http.DefaultTransport and known libraries that use their own transports
// (e.g., go-containerregistry). This affects all HTTP requests made through
// http.DefaultClient and most third-party libraries.
//
// Must be called after Initialize() which sets up the transport.
// The certificate must be in PEM format.
func TrustRoot(pemData string) error {
	poolMu.Lock()
	defer poolMu.Unlock()

	// Initialize pool from system certs on first call
	if rootPool == nil {
		var err error

		rootPool, err = x509.SystemCertPool()
		if err != nil {
			// Fall back to empty pool if system pool unavailable
			rootPool = x509.NewCertPool()
		}
	}

	if !rootPool.AppendCertsFromPEM([]byte(pemData)) {
		return ErrTrustInvalidArgument
	}

	// Access the embedded transport via type assertion
	roundTripper, ok := http.DefaultTransport.(*network.RoundTripper)
	if !ok {
		panic("TrustRoot called before Initialize() - call Initialize() first")
	}

	if roundTripper.TLSClientConfig == nil {
		panic("TLSClientConfig not set - this should not happen after Initialize()")
	}

	// Trust only our configured root CAs
	roundTripper.TLSClientConfig.RootCAs = rootPool

	return nil
}
