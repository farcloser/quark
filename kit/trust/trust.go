// Package trust provides functions for configuring TLS certificate trust.
package trust

import (
	"crypto/x509"
	"net/http"
	"sync"
)

//nolint:gochecknoglobals // Singleton pattern: global cert pool modified via AddRootCA, used by all HTTP clients.
var (
	poolMu   sync.Mutex
	rootPool *x509.CertPool
)

// AddRootCA adds a root CA certificate to the system pool and configures
// both http.DefaultTransport and known libraries that use their own transports
// (e.g., go-containerregistry). This affects all HTTP requests made through
// http.DefaultClient and most third-party libraries.
//
// The certificate must be in PEM format.
func AddRootCA(pemData string) error {
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
		return ErrNoCertificates
	}

	// Configure http.DefaultTransport for well-behaved libraries
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		panic("http DefaultTransport has been tampered with")
	}

	if transport.TLSClientConfig == nil {
		panic("you must call Harden before setting up new roots")
	}

	// Trust only our configured root CAs
	transport.TLSClientConfig.RootCAs = rootPool

	return nil
}
