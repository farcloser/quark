// Package trust provides functions for configuring TLS certificate trust.
package trust

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

var (
	// ErrNoCertificates indicates no valid certificates were found in the provided PEM data.
	ErrNoCertificates = errors.New("no valid certificates found in PEM data")
	// ErrReadCertificate indicates failure reading a certificate file.
	ErrReadCertificate = errors.New("failed to read certificate file")
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
func AddRootCA(pemData []byte) error {
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

	if !rootPool.AppendCertsFromPEM(pemData) {
		return ErrNoCertificates
	}

	configureTransports(rootPool)

	return nil
}

// AddRootCAFromFile reads a PEM certificate file and adds it to the trust store.
func AddRootCAFromFile(path string) error {
	//nolint:gosec // G304: User-provided path is intentional.
	pemData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrReadCertificate, err)
	}

	return AddRootCA(pemData)
}

// configureTransports updates all known transports to use the given cert pool.
func configureTransports(pool *x509.CertPool) {
	// Configure http.DefaultTransport for well-behaved libraries
	configureHTTPTransport(http.DefaultTransport, pool)

	// Configure go-containerregistry's DefaultTransport (it ignores http.DefaultTransport)
	configureHTTPTransport(remote.DefaultTransport, pool)
}

// configureHTTPTransport configures a transport to use the given cert pool.
func configureHTTPTransport(rt http.RoundTripper, pool *x509.CertPool) {
	transport, ok := rt.(*http.Transport)
	if !ok {
		return
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	transport.TLSClientConfig.RootCAs = pool
}
