package sdk

import (
	"fmt"
	"log/slog"

	"github.com/farcloser/quark/dev/resource"
)

// Directory represents a local filesystem directory.
type Directory struct {
	resource.Resource

	options DirectoryOpts
	log     *slog.Logger
}

// DirectoryOpts contains configuration options for creating a directory reference.
type DirectoryOpts struct {
	// Moniker holds plan-defined metadata used purely for display
	Moniker string
	// Path is the local filesystem path for the directory
	Path string
}

// Moniker returns the directory display name.
func (d *Directory) Moniker() string {
	moniker := d.options.Moniker
	if moniker == "" {
		moniker = d.options.Path
	}

	return fmt.Sprintf("%s:%s", directoryResourceName, moniker)
}

// Path returns the directory filesystem path.
func (d *Directory) Path() string {
	return d.options.Path
}

// Copy copies this directory's runtime state to another directory.
func (d *Directory) Copy(dest resource.Resource) error {
	destDir, ok := dest.(*Directory)
	if !ok {
		d.log.Error("Copy: destination is not a Directory, skipping", "dest", fmt.Sprintf("%T", dest))

		return nil
	}

	// Copy options (path may be enriched during execution)
	destDir.options = d.options

	return nil
}

// With creates a new Directory that depends on the current directory and additional resources.
// Use this to express ordering constraints when there's no direct data dependency.
// Returns a new Directory for chaining.
func (d *Directory) With(deps ...resource.Resource) *Directory {
	output := &Directory{
		options: d.options,
		log:     d.log,
	}

	output.Resource = resource.NewWithAction("with:"+d.Moniker(), d, deps...).
		AddOutput(d.Moniker(), output, d)

	return output
}
