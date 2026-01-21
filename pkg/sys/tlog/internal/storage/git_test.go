package storage_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"gotest.tools/v3/assert"

	"github.com/farcloser/quark/pkg/core/filesystem"
	"github.com/farcloser/quark/pkg/core/sshprime"
	"github.com/farcloser/quark/pkg/core/trust"
	"github.com/farcloser/quark/pkg/sys/tlog/internal/storage"
)

func generateTestKey(t *testing.T) sshprime.Key {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	key, err := sshprime.NewKey(pem.EncodeToMemory(block), nil, false)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	return key
}

func testAuthor(t *testing.T) *storage.Author {
	t.Helper()

	return &storage.Author{
		Name:  "Test User",
		Email: "test@example.com",
		Key:   generateTestKey(t),
	}
}

const testGenesis = `{"type":"genesis","version":1}`

// cleanupTestRepo removes any leftover repo from previous test runs.
func cleanupTestRepo(t *testing.T, url string) {
	t.Helper()

	cacheDir, err := filesystem.CacheDir("tlogs")
	if err != nil {
		return // Can't clean up, but don't fail
	}

	repoPath := filepath.Join(cacheDir, trust.HashString(url))
	_ = os.RemoveAll(repoPath)
}

func TestNewRepo_InitWithGenesis(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	author := testAuthor(t)
	url := "git@localhost:test/" + t.Name() + ".git"

	cleanupTestRepo(t, url)

	repo, err := storage.NewBackend(ctx, url, author, testGenesis)
	assert.NilError(t, err)
	assert.Assert(t, repo != nil)

	// Verify we can get HEAD
	head, err := repo.Head()
	assert.NilError(t, err)
	assert.Assert(t, head != "")
}

func TestRepo_Commit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	author := testAuthor(t)
	url := "git@localhost:test/" + t.Name() + ".git"

	cleanupTestRepo(t, url)

	repo, err := storage.NewBackend(ctx, url, author, testGenesis)
	assert.NilError(t, err)

	// Get initial HEAD
	head1, err := repo.Head()
	assert.NilError(t, err)

	// Create a new commit
	hash, err := repo.AddEvent(`{"type":"event","entity":"test","digest":"sha256:abc"}`)
	assert.NilError(t, err)
	assert.Assert(t, hash != "")
	assert.Assert(t, hash != head1)

	// Verify HEAD changed
	head2, err := repo.Head()
	assert.NilError(t, err)
	assert.Equal(t, head2, hash)
}

func TestRepo_Commits(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	author := testAuthor(t)
	url := "git@localhost:test/" + t.Name() + ".git"

	cleanupTestRepo(t, url)

	repo, err := storage.NewBackend(ctx, url, author, testGenesis)
	assert.NilError(t, err)

	// Add a few commits
	_, err = repo.AddEvent(`{"type":"event","entity":"a","digest":"sha256:111"}`)
	assert.NilError(t, err)

	_, err = repo.AddEvent(`{"type":"event","entity":"b","digest":"sha256:222"}`)
	assert.NilError(t, err)

	// Iterate commits
	iter, err := repo.ListEvents()
	assert.NilError(t, err)

	count := 0
	for {
		commit, err := iter.Next()
		if err == io.EOF {
			break
		}

		assert.NilError(t, err)
		assert.Assert(t, commit.Hash != "")
		count++
	}

	// Genesis + 2 events = 3 commits
	assert.Equal(t, count, 3)
}

func TestRepo_IsAncestor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	author := testAuthor(t)
	url := "git@localhost:test/" + t.Name() + ".git"

	cleanupTestRepo(t, url)

	repo, err := storage.NewBackend(ctx, url, author, testGenesis)
	assert.NilError(t, err)

	// Get genesis commit
	genesis, err := repo.Head()
	assert.NilError(t, err)

	// Add commits
	hash1, err := repo.AddEvent(`{"type":"event","entity":"a","digest":"sha256:111"}`)
	assert.NilError(t, err)

	hash2, err := repo.AddEvent(`{"type":"event","entity":"b","digest":"sha256:222"}`)
	assert.NilError(t, err)

	// genesis is ancestor of hash1
	isAnc, err := repo.IsAncestor(genesis, hash1)
	assert.NilError(t, err)
	assert.Assert(t, isAnc)

	// genesis is ancestor of hash2
	isAnc, err = repo.IsAncestor(genesis, hash2)
	assert.NilError(t, err)
	assert.Assert(t, isAnc)

	// hash1 is ancestor of hash2
	isAnc, err = repo.IsAncestor(hash1, hash2)
	assert.NilError(t, err)
	assert.Assert(t, isAnc)

	// hash2 is NOT ancestor of hash1
	isAnc, err = repo.IsAncestor(hash2, hash1)
	assert.NilError(t, err)
	assert.Assert(t, !isAnc)
}

func TestRepo_GetCommitSignatureFingerprint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	author := testAuthor(t)
	url := "git@localhost:test/" + t.Name() + ".git"

	cleanupTestRepo(t, url)

	repo, err := storage.NewBackend(ctx, url, author, testGenesis)
	assert.NilError(t, err)

	head, err := repo.Head()
	assert.NilError(t, err)

	// Get signature fingerprint - should match author's key
	fingerprint, err := repo.GetEventSignatureFingerprint(head)
	assert.NilError(t, err)
	assert.Equal(t, fingerprint, author.Key.Fingerprint())
}

func TestRepo_ReopenExisting(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	author := testAuthor(t)
	url := "git@localhost:test/" + t.Name() + ".git"

	cleanupTestRepo(t, url)

	// First open - creates repo
	repo1, err := storage.NewBackend(ctx, url, author, testGenesis)
	assert.NilError(t, err)

	hash1, err := repo1.AddEvent(`{"type":"event","entity":"test","digest":"sha256:abc"}`)
	assert.NilError(t, err)

	// Second open - should reuse existing repo
	repo2, err := storage.NewBackend(ctx, url, author, "") // empty genesis - must exist
	assert.NilError(t, err)

	head, err := repo2.Head()
	assert.NilError(t, err)
	assert.Equal(t, head, hash1)
}
