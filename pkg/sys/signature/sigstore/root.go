package sigstore

import (
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"

	"github.com/farcloser/quark/internal/types"
	"github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/fault"
)

const (
	cacheDirLocation = "rekor_tuf_root"
)

// NewRoot returns a trust root for Rekor.
func NewRoot(defaultRoot string) types.Root {
	tr := &tufRoot{}
	if defaultRoot != "" {
		_ = tr.FromBytes([]byte(defaultRoot))
	}

	return tr
}

type tufRoot struct {
	root *types.Trusted
}

func (tuffr *tufRoot) Get() *types.Trusted {
	return tuffr.root
}

func (tuffr *tufRoot) FromBytes(data []byte) error {
	trustedRoot, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		return fmt.Errorf("%w: %w", fault.ErrInvalidArgument, err)
	}

	tuffr.root = trustedRoot

	return nil
}

func (tuffr *tufRoot) FromNetwork() error {
	cacheDir, err := filesystem.CacheDir(cacheDirLocation)
	//nolint:wrapcheck
	if err != nil {
		return err
	}

	lock, err := filesystem.Lock(cacheDir)
	//nolint:wrapcheck
	if err != nil {
		return err
	}

	defer func() {
		_ = filesystem.Unlock(lock)
	}()

	// FIXME: allow self-hosted Rekor
	netRoot, err := root.FetchTrustedRootWithOptions(tuf.DefaultOptions().WithCachePath(cacheDir))
	if err != nil {
		return fmt.Errorf("%w: %w", fault.ErrNetworkError, err)
	}

	tuffr.root = netRoot

	return nil
}
