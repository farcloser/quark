package sdk

import (
	"context"
	"strings"

	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/reference"
)

// createImageAction initializes an image by parsing its reference.
type createImageAction struct {
	*resource.BaseAction

	output *Image
}

func (a *createImageAction) AddOutput(
	name string,
	out resource.Resource,
	copyFrom ...resource.Resource,
) resource.Resource {
	return resource.RegisterOutput(a, a.BaseAction, name, out, copyFrom...)
}

// Execute initializes the image reference by parsing the options.
func (a *createImageAction) Execute(ctx context.Context) error {
	img := a.output
	logger := a.output.log

	name := strings.TrimSpace(img.options.Name)
	if name == "" {
		return ErrImageNameRequired
	}

	refString := ""
	if img.registry.options.Domain != "" {
		refString = img.registry.options.Domain + "/"
	}

	refString += name

	if img.options.Version != "" {
		refString += ":" + img.options.Version
	}

	if img.options.Digest != "" {
		refString += "@" + img.options.Digest
	}

	var err error

	img.ref, err = reference.Parse(refString)
	if err != nil {
		return ErrInvalidImageReference
	}

	logger.DebugContext(ctx, "image creation executed")

	return nil
}
