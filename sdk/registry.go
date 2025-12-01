package sdk

// RegistryOpts contains configuration options for creating a registry.
type RegistryOpts struct {
	Domain   string // Required - registry domain (e.g., "ghcr.io", "docker.io")
	Username string // Optional - registry username
	Token    string // Optional - registry token or password
}

// NewRegistry creates a new Registry from the provided arguments.
// Empty domain is normalized to "docker.io" (Docker Hub default).
func NewRegistry(args *RegistryOpts) *Registry {
	domain := args.Domain
	if domain == "" {
		domain = "docker.io"
	}

	return &Registry{
		domain:   domain,
		username: args.Username,
		token:    args.Token,
	}
}

// Registry represents a container registry with authentication.
type Registry struct {
	domain   string
	username string
	token    string
}

// Domain returns the registry domain.
func (r *Registry) Domain() string {
	return r.domain
}

// Username returns the registry username.
func (r *Registry) Username() string {
	return r.username
}

// Token returns the registry token or password.
func (r *Registry) Token() string {
	return r.token
}
