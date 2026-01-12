package sigstore

import (
	"encoding/json"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"

	"github.com/farcloser/quark/dev/fault"
	"github.com/farcloser/quark/dev/filesystem"
	"github.com/farcloser/quark/internal/types"
)

const (
	cacheDirLocation = "rekor_tuf_root"
)

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
	trustedRoot := &types.Trusted{}
	err := json.Unmarshal(data, trustedRoot)
	if err != nil {
		return fmt.Errorf("%w: %w", fault.ErrInvalidArgument, err)
	}

	tuffr.root = trustedRoot

	return nil
}

func (tuffr *tufRoot) FromNetwork() error {
	cacheDir, err := filesystem.CacheDir(cacheDirLocation)
	if err != nil {
		return err
	}

	lock, err := filesystem.Lock(cacheDir)
	if err != nil {
		return err
	}

	defer func() {
		_ = filesystem.Unlock(lock)
	}()

	// FIXME: allow self-hosted Rekor
	netRoot, err := root.FetchTrustedRootWithOptions(tuf.DefaultOptions().WithCachePath(cacheDir))

	if err != nil {
		return err
	}

	tuffr.root = netRoot

	return nil
}
