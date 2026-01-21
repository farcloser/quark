// Package git provides a minimal git client for tlog operations.
// It wraps go-git with only the functionality needed for append-only logs:
// empty signed commits, fetch, push with retry, and commit iteration.
package git

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"

	"github.com/farcloser/quark/pkg/core/sshprime"
	"github.com/farcloser/quark/pkg/fault"
)

// Repo represents a git repository for tlog operations.
type Repo struct {
	repo *git.Repository
	auth gitssh.AuthMethod
}

// Author identifies a commit author.
type Author struct {
	Name  string
	Email string
	Key   sshprime.Key
}

// Commit represents a git commit.
type Commit struct {
	Hash    string
	Message string
	Author  Author
	Time    time.Time
	Parents []string
}

// Open opens an existing git repository.
func Open(path string, auth gitssh.AuthMethod) (*Repo, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		if errors.Is(err, git.ErrRepositoryNotExists) {
			return nil, fmt.Errorf("%w: %s", fault.ErrInvalidArgument, path)
		}

		return nil, fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	r := &Repo{
		repo: repo,
		auth: auth,
	}

	return r, nil
}

// Clone clones a remote repository.
func Clone(ctx context.Context, url, path string, auth gitssh.AuthMethod) (*Repo, error) {
	repo, err := git.PlainCloneContext(ctx, path, false, &git.CloneOptions{
		URL:  url,
		Auth: auth,
	})
	if err != nil {
		if errors.Is(err, transport.ErrAuthenticationRequired) {
			return nil, fmt.Errorf("%w: %w", fault.ErrAuthenticationFailure, err)
		}

		return nil, fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	return &Repo{
		repo: repo,
		auth: auth,
	}, nil
}

// Init initializes a new git repository.
func Init(path string) (*Repo, error) {
	repo, err := git.PlainInit(path, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", fault.ErrWriteFailure, err)
	}

	return &Repo{repo: repo}, nil
}

// SetAuth sets the authentication method for remote operations.
func (r *Repo) SetAuth(auth gitssh.AuthMethod) {
	r.auth = auth
}

// Head returns the current HEAD commit hash.
func (r *Repo) Head() (string, error) {
	ref, err := r.repo.Head()
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return "", ErrNoCommits
		}

		return "", fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	return ref.Hash().String(), nil
}

// Fetch fetches from the remote.
func (r *Repo) Fetch(ctx context.Context, remote string) error {
	err := r.repo.FetchContext(ctx, &git.FetchOptions{
		Auth:       r.auth,
		RemoteName: remote,
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		if errors.Is(err, transport.ErrAuthenticationRequired) {
			return fmt.Errorf("%w: %w", fault.ErrAuthenticationFailure, err)
		}

		return fmt.Errorf("%w: %w", fault.ErrReadFailure, err)
	}

	return nil
}

// Push pushes to the remote.
func (r *Repo) Push(ctx context.Context, remote string) error {
	err := r.repo.PushContext(ctx, &git.PushOptions{
		RemoteName: remote,
		Auth:       r.auth,
	})
	if err != nil {
		if errors.Is(err, git.NoErrAlreadyUpToDate) {
			return nil
		}

		if errors.Is(err, git.ErrNonFastForwardUpdate) {
			return ErrNonFastForward
		}

		if errors.Is(err, transport.ErrAuthenticationRequired) {
			return fmt.Errorf("%w: %w", fault.ErrAuthenticationFailure, err)
		}

		return fmt.Errorf("%w: %w", fault.ErrWriteFailure, err)
	}

	return nil
}

// AddRemote adds a remote to the repository.
func (r *Repo) AddRemote(name, url string) error {
	_, err := r.repo.CreateRemote(&config.RemoteConfig{
		Name: name,
		URLs: []string{url},
	})
	if err != nil {
		return fmt.Errorf("add remote: %w", err)
	}

	return nil
}

// RemoteURL returns the fetch URL for the named remote.
// Returns an error if the remote doesn't exist or has no URLs.
func (r *Repo) RemoteURL(name string) (string, error) {
	remote, err := r.repo.Remote(name)
	if err != nil {
		return "", fmt.Errorf("get remote %s: %w", name, err)
	}

	cfg := remote.Config()
	if len(cfg.URLs) == 0 {
		return "", fmt.Errorf("remote %s: %w", name, ErrRemoteNoURLs)
	}

	return cfg.URLs[0], nil
}

// RemoteHead returns the commit hash of the remote tracking branch.
// Returns empty string if the remote branch doesn't exist (e.g., never fetched).
func (r *Repo) RemoteHead(remote, branch string) (string, error) {
	ref, err := r.repo.Reference(
		plumbing.NewRemoteReferenceName(remote, branch),
		true,
	)
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return "", nil
		}

		return "", fmt.Errorf("get remote ref %s/%s: %w", remote, branch, err)
	}

	return ref.Hash().String(), nil
}

// CreateEmptyCommit creates a signed empty commit with the given message.
// The commit has no file changes, only a message and signature.
// Signing is mandatory - the signer is resolved from author.Key or git config.
func (r *Repo) CreateEmptyCommit(message string, author *Author, when time.Time) (string, error) {
	signer, err := r.resolveSigner(author.Key)
	if err != nil {
		return "", fmt.Errorf("resolve signer: %w", err)
	}

	// Get the worktree to access commit functionality.
	worktree, err := r.repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("get worktree: %w", err)
	}

	opts := &git.CommitOptions{
		Author: &object.Signature{
			Name:  author.Name,
			Email: author.Email,
			When:  when,
		},
		Signer:            newSSHSigner(signer),
		AllowEmptyCommits: true,
	}

	hash, err := worktree.Commit(message, opts)
	if err != nil {
		return "", fmt.Errorf("create commit: %w", err)
	}

	return hash.String(), nil
}

// Commits returns an iterator over commits starting from HEAD.
func (r *Repo) Commits() (*CommitIter, error) {
	ref, err := r.repo.Head()
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return nil, ErrNoCommits
		}

		return nil, fmt.Errorf("get HEAD: %w", err)
	}

	iter, err := r.repo.Log(&git.LogOptions{
		From:  ref.Hash(),
		Order: git.LogOrderCommitterTime,
	})
	if err != nil {
		return nil, fmt.Errorf("get log: %w", err)
	}

	return &CommitIter{iter: iter}, nil
}

// CommitIter iterates over commits.
type CommitIter struct {
	iter object.CommitIter
}

// Next returns the next commit or io.EOF when done.
func (ci *CommitIter) Next() (*Commit, error) {
	commit, err := ci.iter.Next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}

		return nil, fmt.Errorf("next commit: %w", err)
	}

	parents := make([]string, len(commit.ParentHashes))
	for i, hash := range commit.ParentHashes {
		parents[i] = hash.String()
	}

	return &Commit{
		Hash:    commit.Hash.String(),
		Message: commit.Message,
		Author: Author{
			Name:  commit.Author.Name,
			Email: commit.Author.Email,
		},
		Time:    commit.Author.When,
		Parents: parents,
	}, nil
}

// Close closes the iterator.
func (ci *CommitIter) Close() {
	ci.iter.Close()
}

// GetCommit retrieves a specific commit by hash.
func (r *Repo) GetCommit(hash string) (*Commit, error) {
	plumbingHash := plumbing.NewHash(hash)

	commit, err := r.repo.CommitObject(plumbingHash)
	if err != nil {
		return nil, fmt.Errorf("get commit %s: %w", hash, err)
	}

	parents := make([]string, len(commit.ParentHashes))
	for idx, parentHash := range commit.ParentHashes {
		parents[idx] = parentHash.String()
	}

	return &Commit{
		Hash:    commit.Hash.String(),
		Message: commit.Message,
		Author: Author{
			Name:  commit.Author.Name,
			Email: commit.Author.Email,
		},
		Time:    commit.Author.When,
		Parents: parents,
	}, nil
}

// IsAncestor returns true if ancestor is an ancestor of descendant.
func (r *Repo) IsAncestor(ancestor, descendant string) (bool, error) {
	ancestorHash := plumbing.NewHash(ancestor)
	descendantHash := plumbing.NewHash(descendant)

	descendantCommit, err := r.repo.CommitObject(descendantHash)
	if err != nil {
		return false, fmt.Errorf("get descendant commit: %w", err)
	}

	ancestorCommit, err := r.repo.CommitObject(ancestorHash)
	if err != nil {
		return false, fmt.Errorf("get ancestor commit: %w", err)
	}

	isAnc, err := ancestorCommit.IsAncestor(descendantCommit)
	if err != nil {
		return false, fmt.Errorf("check ancestry: %w", err)
	}

	return isAnc, nil
}

// ResetToRemote resets the local branch to match the remote.
// Used after fetch when local is behind remote.
// NOTE: this IS a destructive operation that will destroy all local changes.
func (r *Repo) ResetToRemote(remote, branch string) error {
	remoteRef, err := r.repo.Reference(
		plumbing.NewRemoteReferenceName(remote, branch),
		true,
	)
	if err != nil {
		return fmt.Errorf("get remote ref: %w", err)
	}

	wt, err := r.repo.Worktree()
	if err != nil {
		return fmt.Errorf("get worktree: %w", err)
	}

	err = wt.Reset(&git.ResetOptions{
		Commit: remoteRef.Hash(),
		Mode:   git.HardReset,
	})
	if err != nil {
		return fmt.Errorf("reset: %w", err)
	}

	return nil
}
