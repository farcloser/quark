package sdk

import (
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/dev/ssh"
)

// Node represents a remote SSH-accessible node.
type Node struct {
	resource.Resource

	options     NodeOpts
	log         *slog.Logger
	concurrency int // max concurrent builds

	conn ssh.Connection
}

// NodeOpts configures node creation.
type NodeOpts struct {
	// Moniker holds plan-defined metadata used purely for display
	Moniker     string
	Endpoint    string // Required - SSH endpoint (IP, hostname, or SSH config alias)
	Fingerprint string // Optional - SSH host key fingerprint for verification
	SSHKey      string // Optional - PEM-encoded SSH private key content
	Concurrency int    // Optional - max concurrent builds (defaults to 1)
}

// NewNode creates a new Node resource.
func NewNode(opts NodeOpts) *Node {
	moniker := opts.Moniker
	if moniker == "" {
		moniker = opts.Endpoint
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = defaultNodeConcurrency
	}

	output := &Node{
		options:     opts,
		log:         slog.With(nodeResourceName, moniker),
		concurrency: concurrency,
	}

	moniker = fmt.Sprintf("%s:%s", nodeResourceName, moniker)

	output.Resource = (&createNodeAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionCreateName, moniker)),
		output:     output,
	}).AddOutput(moniker, output)

	return output
}

// Moniker returns the node name.
func (n *Node) Moniker() string {
	moniker := n.options.Moniker
	if moniker == "" {
		moniker = n.options.Endpoint
	}

	return fmt.Sprintf("%s:%s", nodeResourceName, moniker)
}

// Connection returns the SSH connection for this node.
// Must be called after Execute has completed successfully.
func (n *Node) Connection() ssh.Connection {
	return n.conn
}

// Active returns the number of builds currently running on this node.
func (n *Node) Active() int {
	return defaultScheduler.Active(n)
}

// Available returns the number of available build slots on this node.
func (n *Node) Available() int {
	return defaultScheduler.Available(n)
}
