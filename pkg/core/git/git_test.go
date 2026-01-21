package git_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"gotest.tools/v3/assert"

	"github.com/farcloser/quark/pkg/core/git"
	"github.com/farcloser/quark/pkg/core/sshprime"
	"github.com/farcloser/quark/pkg/fault"
)

// generateTestKey generates an ed25519 key and returns it as PEM bytes for testing.
func generateTestKey(t *testing.T) []byte {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	return pem.EncodeToMemory(block)
}

// mustNewKey creates a sshprime.Key from bytes or fails the test.
func mustNewKey(t *testing.T, bytes []byte) sshprime.Key {
	t.Helper()

	key, err := sshprime.NewKey(bytes, nil, false)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	return key
}

func TestInit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)
	assert.Assert(t, repo != nil)

	// Verify .git directory exists.
	_, err = os.Stat(filepath.Join(dir, ".git"))
	assert.NilError(t, err)
}

func TestOpen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Init first.
	_, err := git.Init(dir)
	assert.NilError(t, err)

	// Open existing.
	repo, err := git.Open(dir, nil)
	assert.NilError(t, err)
	assert.Assert(t, repo != nil)
}

func TestOpenNonExistent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, err := git.Open(dir, nil)
	assert.ErrorIs(t, err, fault.ErrInvalidArgument)
}

func TestCreateEmptyCommit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	key := mustNewKey(t, generateTestKey(t))

	// Create signed commit.
	hash, err := repo.CreateEmptyCommit(
		"test commit message",
		&git.Author{
			Name:  "Test User",
			Email: "test@example.com",
			Key:   key,
		},
		time.Now(),
	)
	assert.NilError(t, err)
	assert.Assert(t, len(hash) == 40, "expected 40-char hash, got %d", len(hash))

	// Verify HEAD.
	head, err := repo.Head()
	assert.NilError(t, err)
	assert.Equal(t, hash, head)
}

func TestCommitIteration(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	key := mustNewKey(t, generateTestKey(t))

	// Create multiple commits.
	messages := []string{"first", "second", "third"}
	for _, msg := range messages {
		_, err := repo.CreateEmptyCommit(
			msg,
			&git.Author{
				Name:  "Test",
				Email: "test@example.com",
				Key:   key,
			},
			time.Now(),
		)
		assert.NilError(t, err)
	}

	// Iterate commits (newest first).
	iter, err := repo.Commits()
	assert.NilError(t, err)

	defer iter.Close()

	var found []string

	for {
		commit, err := iter.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		assert.NilError(t, err)

		found = append(found, commit.Message)
	}

	// Should be in reverse order (newest first).
	assert.Equal(t, len(found), 3)
	assert.Equal(t, found[0], "third")
	assert.Equal(t, found[1], "second")
	assert.Equal(t, found[2], "first")
}

func TestGetCommit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	key := mustNewKey(t, generateTestKey(t))

	hash, err := repo.CreateEmptyCommit(
		"test message",
		&git.Author{
			Name:  "Test",
			Email: "test@example.com",
			Key:   key,
		},
		time.Now(),
	)
	assert.NilError(t, err)

	commit, err := repo.GetCommit(hash)
	assert.NilError(t, err)
	assert.Equal(t, commit.Hash, hash)
	assert.Equal(t, commit.Message, "test message")
	assert.Equal(t, commit.Author.Name, "Test")
}

func TestIsAncestor(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	key := mustNewKey(t, generateTestKey(t))
	author := &git.Author{Name: "Test", Email: "test@example.com", Key: key}

	// Create chain: A -> B -> C
	hashA, err := repo.CreateEmptyCommit("A", author, time.Now())
	assert.NilError(t, err)

	hashB, err := repo.CreateEmptyCommit("B", author, time.Now())
	assert.NilError(t, err)

	hashC, err := repo.CreateEmptyCommit("C", author, time.Now())
	assert.NilError(t, err)

	// A is ancestor of C.
	isAnc, err := repo.IsAncestor(hashA, hashC)
	assert.NilError(t, err)
	assert.Assert(t, isAnc, "A should be ancestor of C")

	// A is ancestor of B.
	isAnc, err = repo.IsAncestor(hashA, hashB)
	assert.NilError(t, err)
	assert.Assert(t, isAnc, "A should be ancestor of B")

	// C is not ancestor of A.
	isAnc, err = repo.IsAncestor(hashC, hashA)
	assert.NilError(t, err)
	assert.Assert(t, !isAnc, "C should not be ancestor of A")
}

func TestHeadNoCommits(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	_, err = repo.Head()
	assert.ErrorIs(t, err, git.ErrNoCommits)
}

func TestCommitsNoCommits(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	repo, err := git.Init(dir)
	assert.NilError(t, err)

	_, err = repo.Commits()
	assert.ErrorIs(t, err, git.ErrNoCommits)
}

func TestRemoteHead(t *testing.T) {
	t.Parallel()

	// Create "upstream" repo with a commit.
	upstreamDir := t.TempDir()
	upstream, err := git.Init(upstreamDir)
	assert.NilError(t, err)

	key := mustNewKey(t, generateTestKey(t))
	author := &git.Author{Name: "Test", Email: "test@example.com", Key: key}

	commitHash, err := upstream.CreateEmptyCommit("upstream commit", author, time.Now())
	assert.NilError(t, err)

	// Create "local" repo and add upstream as remote.
	localDir := t.TempDir()
	local, err := git.Init(localDir)
	assert.NilError(t, err)

	err = local.AddRemote("origin", upstreamDir)
	assert.NilError(t, err)

	// Before fetch: remote head should be empty (not error).
	remoteHead, err := local.RemoteHead("origin", "master")
	assert.NilError(t, err)
	assert.Equal(t, remoteHead, "", "expected empty before fetch")

	// Fetch from upstream.
	ctx := t.Context()
	err = local.Fetch(ctx, "origin")
	assert.NilError(t, err)

	// After fetch: remote head should match upstream commit.
	remoteHead, err = local.RemoteHead("origin", "master")
	assert.NilError(t, err)
	assert.Equal(t, remoteHead, commitHash)
}
