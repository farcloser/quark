package builder

import (
	"context"
	"fmt"

	"github.com/farcloser/quark/pkg/dev/store"
)

// PrepareSecrets writes secrets to content-addressed files and returns SecretFile handles.
// Each SecretFile holds a read lock preventing deletion while in use.
// The caller must call Release() on each SecretFile when done.
func PrepareSecrets(secrets []struct{ ID, Content string }) ([]*SecretFile, error) {
	if len(secrets) == 0 {
		return nil, nil
	}

	result := make([]*SecretFile, 0, len(secrets))

	for _, secret := range secrets {
		path, release, err := store.GetStoreVolatile().Acquire([]byte(secret.Content))
		if err != nil {
			// Clean up any secrets we already prepared
			for _, prepared := range result {
				prepared.Release()
			}

			return nil, fmt.Errorf("%w: %w", ErrPrepareSecrets, err)
		}

		result = append(result, &SecretFile{
			ID:      secret.ID,
			Path:    path,
			release: release,
		})
	}

	return result, nil
}

// BuildOptions configures a build operation.
type BuildOptions struct {
	ContextPath    string
	DockerfilePath string
	Platforms      []string
	Tags           []string // if set, push to registry
	DestPath       string   // if set, export to local directory
	BuildArgs      map[string]string
	Target         string
	ExtraHosts     []string
	Secrets        []*SecretFile
	NoLog          bool
}

// Client provides container image building operations.
type Client interface {
	// Close releases resources held by the client.
	Close() error

	// Build builds container images for multiple platforms.
	// If Tags is set, pushes to registry and returns the manifest digest.
	// If DestPath is set, exports to local directory and returns empty string.
	Build(ctx context.Context, opts BuildOptions) (string, error)
}
