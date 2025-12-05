package network

import (
	"crypto/tls"
	"net/http"
)

// SetDefaults updates all known transports to use the given cert pool.
func SetDefaults() {
	// SetDefaults http.DefaultTransport for well-behaved libraries
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		panic("default transport has been tampered with")
	}

	// Proxy configuration
	transport.Proxy = http.ProxyFromEnvironment

	// Enable HTTP/2 - required when setting custom TLSClientConfig
	transport.ForceAttemptHTTP2 = true

	// Connection pool tuning - prevent connection churn
	// Default MaxIdleConnsPerHost is 2, causing excessive TIME_WAIT sockets
	transport.MaxIdleConns = 100        //revive:disable-line:add-constant
	transport.MaxIdleConnsPerHost = 100 //revive:disable-line:add-constant
	transport.MaxConnsPerHost = 100     //revive:disable-line:add-constant

	// Assign TLS config
	transport.TLSClientConfig = defaultTLSConfig()
}

func defaultTLSConfig() *tls.Config {
	return &tls.Config{
		// TLS 1.3 only - TLS 1.2 should be considered legacy in 2025
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, // Post-quantum hybrid (preferred)
			tls.X25519,         // Modern ECDH fallback
		},
	}
}
