package types //revive:disable-line:var-naming

// RegistryCredentials provides a simple struct to pass along registry authentication information.
type RegistryCredentials struct {
	Domain string
	// Basic auth
	Username string
	Password string
	// Bearer Token auth
	Token string
	// MTLS auth
	Cert string
	Key  string
	// Additional CA to be used specifically for a registry
	CA string
}
