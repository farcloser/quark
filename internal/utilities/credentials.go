package utilities //revive:disable-line:var-naming

// RegistryCredentials provides a simple struct to pass along registry authentication information.
type RegistryCredentials struct {
	Domain   string
	Username string
	Token    string
}
