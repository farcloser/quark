package sdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
)

type createDirectoryAction struct {
	*resource.BaseAction

	output *Directory
}

func (ca *createDirectoryAction) AddOutput(
	name string,
	out resource.Resource,
	copyFrom ...resource.Resource,
) resource.Resource {
	return resource.RegisterOutput(ca, ca.BaseAction, name, out, copyFrom...)
}

func (ca *createDirectoryAction) Execute(_ context.Context) error {
	// Nothing to do - directory path is set at construction time
	return nil
}

// NewDirectory creates a new Directory with the given options.
func NewDirectory(opts DirectoryOpts) *Directory {
	moniker := opts.Moniker
	if moniker == "" {
		moniker = opts.Path
	}

	output := &Directory{
		options: opts,
		log:     slog.With(directoryResourceName, moniker),
	}

	moniker = fmt.Sprintf("%s:%s", directoryResourceName, moniker)

	output.Resource = (&createDirectoryAction{
		BaseAction: resource.NewAction(fmt.Sprintf("%s:%s", actionCreateName, moniker)),
		output:     output,
	}).AddOutput(moniker, output)

	return output
}
