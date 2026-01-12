package sdk

import (
	"context"

	"github.com/farcloser/quark/dev/resource"
)

// createBuilderAction initializes a builder.
type createBuilderAction struct {
	*resource.BaseAction

	output *Builder
}

func (cba *createBuilderAction) AddOutput(
	name string,
	out resource.Resource,
	copyFrom ...resource.Resource,
) resource.Resource {
	return resource.RegisterOutput(cba, cba.BaseAction, name, out, copyFrom...)
}

// Execute validates the builder configuration.
func (cba *createBuilderAction) Execute(ctx context.Context) error {
	logger := cba.output.log
	// Could validate Dockerfile path here in the future
	logger.DebugContext(ctx, "builder created executed")

	return nil
}
