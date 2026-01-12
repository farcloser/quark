package sdk

import (
	"context"

	"github.com/farcloser/quark/dev/resource"
)

// createSignerAction initializes a signer.
// Currently, a no-op, but could validate keys in the future.
type createSignerAction struct {
	*resource.BaseAction

	output *Signer
}

func (a *createSignerAction) AddOutput(
	name string,
	out resource.Resource,
	copyFrom ...resource.Resource,
) resource.Resource {
	return resource.RegisterOutput(a, a.BaseAction, name, out, copyFrom...)
}

// Execute validates the signer configuration.
func (a *createSignerAction) Execute(ctx context.Context) error {
	logger := a.output.log

	logger.DebugContext(ctx, "signer creation executed")

	return nil
}
