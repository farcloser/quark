package derp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/farcloser/quark/pkg/sys/tlog/internal/storage"
	"github.com/farcloser/quark/pkg/sys/tlog/internal/v1"
)

// Init creates a new tlog with a genesis commit.
// Returns a Log interface backed by the current schema version.
func NewLog(ctx context.Context, url string, author *storage.Author, genesis *GenesisEntry, opts ...Option) (Log, error) {
	if genesis == nil {
		return nil, fmt.Errorf("%w: genesis entry is nil", ErrInvalidGenesis)
	}

	if err := genesis.Operator.Validate(); err != nil {
		return nil, fmt.Errorf("%w: operator: %w", ErrInvalidGenesis, err)
	}

	// Set version to current schema
	genesis.Version = int(CurrentSchema)

	cfg := applyOptions(opts)

	genesisData, err := json.Marshal(genesis)
	if err != nil {
		return nil, err
	}

	repo, err := storage.NewBackend(ctx, url, author, string(genesisData))

	if err != nil {
		return nil, fmt.Errorf("failed to open tlog: %w", err)
	}

	version, err := detectSchemaVersion(repo)
	if err != nil {
		return nil, fmt.Errorf("failed to detect schema version: %w", err)
	}

	return newLogForVersion(version, repo, cfg)
}

// detectSchemaVersion reads the genesis commit to determine the schema version.
func detectSchemaVersion(repo *storage.Backend) (SchemaVersion, error) {
	commits, err := repo.ListEvents()
	if err != nil {
		return 0, fmt.Errorf("failed to get commits: %w", err)
	}

	// Walk to find the genesis (last commit)
	var lastMessage string

	for {
		commit, err := commits.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return 0, fmt.Errorf("failed to read commit: %w", err)
		}

		lastMessage = commit.Message
	}

	if lastMessage == "" {
		return 0, ErrNoGenesis
	}

	// Parse just enough to get the version
	var env struct {
		Type    string `json:"type"`
		Version int    `json:"version"`
	}

	if err := json.Unmarshal([]byte(lastMessage), &env); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidGenesis, err)
	}

	if env.Type != TypeGenesis {
		return 0, fmt.Errorf("%w: first commit is not genesis", ErrInvalidGenesis)
	}

	return SchemaVersion(env.Version), nil
}

// newLogForVersion creates the appropriate Log implementation for a schema version.
func newLogForVersion(version SchemaVersion, repo *storage.Backend, cfg *config) (Log, error) {
	switch version {
	case SchemaV1:
		return &v1.logV1{
			repo:   repo,
			config: cfg,
		}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
}
