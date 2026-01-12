package ssh

// Key is a convenience struct to carry around (optionally passphrase protected) private ssh key.
type Key struct {
	Bytes      []byte
	Passphrase []byte
}

// Endpoint represents an ssh host along with a username.
type Endpoint struct {
	User string
	Host string
	Port int
}
