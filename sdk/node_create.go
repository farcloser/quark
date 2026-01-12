package sdk

import (
	"context"
	"fmt"

	"github.com/farcloser/quark/dev/resource"
)

// createNodeAction validates node configuration and establishes SSH connection.
type createNodeAction struct {
	*resource.BaseAction

	output *Node
}

func (a *createNodeAction) AddOutput(
	name string,
	out resource.Resource,
	copyFrom ...resource.Resource,
) resource.Resource {
	return resource.RegisterOutput(a, a.BaseAction, name, out, copyFrom...)
}

// Execute validates the node configuration and establishes SSH connection.
func (a *createNodeAction) Execute(ctx context.Context) error {
	logger := a.output.log
	node := a.output

	endpoint := node.options.Endpoint
	if endpoint == "" {
		return ErrNodeEndpointRequired
	}

	// Get connection from pool
	pool := getSSHPool()

	conn, err := pool.GetClientWithKey(endpoint, node.options.Fingerprint, node.options.SSHKey)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrNodeConnectionFailed, endpoint, err)
	}

	node.conn = conn

	// Register node with scheduler for capacity management
	defaultScheduler.registerNode(node, node.concurrency)

	logger.DebugContext(ctx, "node creation executed")

	return nil
}
