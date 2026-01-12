package secrets

import "sync"

//nolint:gochecknoglobals // Global resolver with lazy initialization
var (
	globalResolver *Resolver
	resolverOnce   sync.Once
)

// GetResolver returns the global resolver instance, initializing it on first access.
func GetResolver() *Resolver {
	resolverOnce.Do(func() {
		globalResolver = &Resolver{}
	})

	return globalResolver
}
