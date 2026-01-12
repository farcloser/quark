package sdk

import (
	"context"

	"github.com/farcloser/quark/dev/resource"
)

// doAction wraps a user-provided function for custom image operations.
type doAction struct {
	*resource.BaseAction

	output *Image
	fn     func(ctx context.Context, output *Image) error
}

func (da *doAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(da, da.BaseAction, name, out, copyFrom...)
}

// Execute runs the user-provided function.
func (da *doAction) Execute(ctx context.Context) error {
	return da.fn(ctx, da.output)
}
