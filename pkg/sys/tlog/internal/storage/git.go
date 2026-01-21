package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/core/git"
	"github.com/farcloser/quark/pkg/core/trust"
	"github.com/farcloser/quark/pkg/fault"
)

const (
	repoCache  = "tlogs"
	remote     = "tlog"
	maxRetries = 5
	main       = "master" // underlying go git hardcodes to master

)

type Author = git.Author
type CommitIter = git.CommitIter

type Backend struct {
	author  *Author
	gitRepo *git.Repo
}

func (r *Backend) Head() (string, error) {
	return r.gitRepo.Head()
}

func (r *Backend) ListEvents() (*CommitIter, error) {
	return r.gitRepo.Commits()
}

func (r *Backend) IsAncestor(ancestor, descendant string) (bool, error) {
	return r.gitRepo.IsAncestor(ancestor, descendant)
}

// Sync fetches from upstream and fast-forwards local.
// Panics if upstream history was rewritten (tampering detected).
func (r *Backend) Sync(ctx context.Context) error {
	localHead, err := r.Head()
	if err != nil {
		return err
	}

	err = r.gitRepo.Fetch(ctx, remote)
	if err != nil {
		return err
	}

	remoteHead, err := r.gitRepo.RemoteHead(remote, main)
	if err != nil {
		return err
	}

	if localHead != "" && remoteHead != "" {
		isAncestor, err := r.IsAncestor(localHead, remoteHead)
		if err != nil {
			return err
		}

		if !isAncestor {
			panic("TLOG TAMPERING DETECTED: upstream history likely rewritten. ACTIONS MUST BE TAKEN NOW.")
		}
	}

	return r.gitRepo.ResetToRemote(remote, main)
}

// AddEvent commits and pushes with automatic retry on conflict.
// FIXME: implement keyless - need cosign signing for Fulcio / keyless.
func (r *Backend) AddEvent(ctx context.Context, message string) (string, error) {
	for i := 0; i < maxRetries; i++ {
		err := r.Sync(ctx)
		if err != nil {
			return "", err
		}

		hash, err := r.gitRepo.CreateEmptyCommit(message, r.author, time.Now().UTC())
		if err != nil {
			return "", err
		}

		err = r.gitRepo.Push(ctx, remote)
		if err == nil {
			return hash, nil
		}

		if !errors.Is(err, git.ErrNonFastForward) {
			return "", err
		}

		time.Sleep(1 * time.Second)
	}

	return "", ErrSyncConflict
}

func (r *Backend) GetEventSignatureFingerprint(hash string) (string, error) {
	sigInfo, err := r.gitRepo.GetCommitSigner(hash)
	if err != nil {
		if errors.Is(err, git.ErrSignatureMissing) {
			return "", fmt.Errorf("%w: commit %s", ErrUnsignedCommit, hash)
		}

		return "", fmt.Errorf("%w: %w", ErrFailedReadingCommitSignature, err)
	}

	return sigInfo.KeyFingerprint, nil
}

func NewBackend(ctx context.Context, url string, author *Author, genesis string) (*Backend, error) {
	// NOTE: we assume ssh config on for convenience, but this could be made parameterizable.
	auth := git.NewSSHAuth(url, "", author.Key, true)

	tlog := &Backend{
		author: author,
	}

	path, err := filesystem.CacheDir(repoCache)
	if err != nil {
		return nil, err
	}

	repoPath := filepath.Join(path, trust.HashString(url))

	// Yes, that is a write lock. We use it for convenience so that we don't have to swap out from a ro lock to
	// a rw lock with all the toctou dance.
	// Worse case scenario, we hurt concurrency a bit by preventing from accessing another tlog repo until we are done
	// cloning this one (so, seconds, on cold start only).
	lck, err := filesystem.Lock(path)
	defer filesystem.Unlock(lck)

	if err != nil {
		return nil, err
	}

	_, err = os.Stat(repoPath)
	if err == nil {
		repo, err := git.Open(repoPath, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to open git repo: %w", err)
		}

		tlog.gitRepo = repo
		repo.SetAuth(auth)

		return tlog, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %w", fault.ErrFilesystemFailure, err)
	}

	// Try to clone
	repo, err := git.Clone(ctx, url, repoPath, auth)
	if err == nil {
		tlog.gitRepo = repo
		repo.SetAuth(auth)

		return tlog, nil
	}

	if genesis == "" {
		return nil, err
	}

	slog.Warn("failed to clone git repo - creating a new fresh git repo", "err", err)

	repo, err = git.Init(repoPath)
	if err != nil {
		return nil, err
	}

	// Add remote
	err = repo.AddRemote(remote, url)
	if err != nil {
		return nil, err
	}

	// Create genesis commit
	_, err = repo.CreateEmptyCommit(genesis, author, time.Now().UTC())
	if err != nil {
		return nil, err
	}

	tlog.gitRepo = repo
	repo.SetAuth(auth)

	err = repo.Push(ctx, remote)
	if err != nil {
		return nil, err
	}

	return tlog, nil
}
