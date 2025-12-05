package sdk

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/dev/ssh"
)

const (
	nodeResourceName       = "node"
	defaultNodeConcurrency = 1
)

// Node represents a remote SSH-accessible node.
type Node struct {
	resource.BaseResource[Node]

	opts NodeOpts
	log  *slog.Logger
	conn ssh.Connection
	sem  chan struct{} // semaphore for concurrency limiting
}

// NodeOpts configures node creation.
type NodeOpts struct {
	Endpoint    string // Required - SSH endpoint (IP, hostname, or SSH config alias)
	Fingerprint string // Optional - SSH host key fingerprint for verification
	SSHKey      string // Optional - PEM-encoded SSH private key content
	Concurrency int    // Optional - max concurrent builds (defaults to 1)
}

// NewNode creates a new Node resource.
func NewNode(opts NodeOpts) *Node {
	name := fmt.Sprintf("%s:%s", nodeResourceName, strings.TrimSpace(opts.Endpoint))

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = defaultNodeConcurrency
	}

	node := &Node{
		opts: opts,
		log:  slog.With("node", name),
		sem:  make(chan struct{}, concurrency),
	}
	node.BaseResource = resource.NewBaseResource(node, name)

	return node
}

// Execute validates the node configuration and establishes SSH connection.
func (n *Node) Execute(ctx context.Context) error {
	endpoint := strings.TrimSpace(n.opts.Endpoint)
	if endpoint == "" {
		return ErrNodeEndpointRequired
	}

	n.log.DebugContext(ctx, "connecting to node", "endpoint", endpoint)

	// Get connection from pool
	pool := getSSHPool()

	conn, err := pool.GetClientWithKey(endpoint, n.opts.Fingerprint, n.opts.SSHKey)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrNodeConnectionFailed, endpoint, err)
	}

	n.conn = conn
	n.log.DebugContext(ctx, "node connection established", "endpoint", endpoint)

	return nil
}

// Connection returns the SSH connection for this node.
// Must be called after Execute has completed successfully.
func (n *Node) Connection() ssh.Connection {
	return n.conn
}

// Concurrency returns the maximum concurrent builds allowed on this node.
func (n *Node) Concurrency() int {
	return cap(n.sem)
}

// Active returns the number of builds currently running on this node.
func (n *Node) Active() int {
	return len(n.sem)
}

// Available returns the number of available build slots on this node.
func (n *Node) Available() int {
	return cap(n.sem) - len(n.sem)
}

// TryAcquire attempts to acquire a build slot without blocking.
// Returns true if a slot was acquired, false if the node is at capacity.
func (n *Node) TryAcquire() bool {
	select {
	case n.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// Acquire blocks until a build slot is available, respecting context cancellation.
// Returns nil on success, or ctx.Err() if the context is cancelled.
func (n *Node) Acquire(ctx context.Context) error {
	select {
	case n.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err() //nolint:wrapcheck // context errors are self-explanatory sentinels
	}
}

// Release releases a build slot.
func (n *Node) Release() {
	<-n.sem
}
