package resource

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/farcloser/quark/pkg/fault"
)

// Resource is a pure data container.
// Resources have no dependencies and no behavior - they just hold state.
// Every resource is produced by exactly one action.
type Resource interface {
	NodeID() string
	NodeName() string
	// NodeParent returns the action that produces this resource.
	NodeParent() Action
	// Copy copies this resource's runtime state to dest.
	// Concrete resources should override this to copy their specific state.
	Copy(dest Resource) error
}

// Action transforms inputs into outputs.
// Actions are the only things that execute in the DAG.
//
// Concrete actions should embed *BaseAction and implement Execute.
// They must also implement AddOutput to properly register themselves
// as the producing action (use RegisterOutput helper).
type Action interface {
	NodeID() string
	NodeName() string
	// Dependencies returns resources this action depends on.
	// These must be ready before Execute runs.
	Dependencies() []Resource
	// Outputs returns resources this action produces.
	Outputs() []Resource
	// AddOutput registers an output resource and returns its base Resource.
	// Concrete actions MUST implement this method using RegisterOutput
	// to ensure proper type identity is preserved.
	AddOutput(name string, out Resource, copyFrom ...Resource) Resource
	// Bootstrap runs pre-execution setup (e.g., copying state from inputs to outputs).
	// Called automatically by the plan executor before Execute.
	Bootstrap() error
	// Execute performs the action's work, mutating outputs.
	Execute(ctx context.Context) error
}

// idGenerator provides unique IDs for resources and actions.
//
//nolint:gochecknoglobals
var idGenerator atomic.Uint64

// nextID generates a unique ID with the given prefix.
func nextID(prefix string) string {
	seq := idGenerator.Add(1)

	return fmt.Sprintf("%s-%d", prefix, seq)
}

// baseResource provides common functionality for resources.
// Resources are pure data containers with no dependencies.
type baseResource struct {
	id         string
	name       string
	producedBy Action
}

// NodeID implements Resource.
func (br *baseResource) NodeID() string {
	return br.id
}

// NodeName implements Resource.
func (br *baseResource) NodeName() string {
	return br.name
}

// NodeParent() implements Resource.
func (br *baseResource) NodeParent() Action {
	return br.producedBy
}

// Copy returns an error by default.
// Concrete resources should override this to copy their specific state.
func (br *baseResource) Copy(_ Resource) error {
	return fmt.Errorf("%w for resource %s", fault.ErrNotImplemented, br.name)
}

// BaseAction provides common functionality for actions.
// Concrete actions should embed *BaseAction and implement Execute and AddOutput.
//
// Example:
//
//	type myAction struct {
//	    *resource.BaseAction
//	    // custom fields
//	}
//
//	func (a *myAction) Execute(ctx context.Context) error {
//	    // implementation
//	}
//
//	func (a *myAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
//	    return resource.RegisterOutput(a, a.BaseAction, name, out, copyFrom...)
//	}
type BaseAction struct {
	id         string
	name       string
	deps       []Resource
	outputs    []Resource
	bootstraps []func() error
}

// NewAction creates a new BaseAction.
// Concrete actions should embed the returned *BaseAction.
func NewAction(name string, deps ...Resource) *BaseAction {
	return &BaseAction{
		id:   nextID(name),
		name: name,
		deps: deps,
	}
}

// NodeID implements Action.
func (ba *BaseAction) NodeID() string {
	return ba.id
}

// NodeName implements Action.
func (ba *BaseAction) NodeName() string {
	return ba.name
}

// Dependencies implements Action.
func (ba *BaseAction) Dependencies() []Resource {
	return ba.deps
}

// Outputs implements Action.
func (ba *BaseAction) Outputs() []Resource {
	return ba.outputs
}

// Bootstrap runs all registered bootstrap functions.
func (ba *BaseAction) Bootstrap() error {
	for _, fn := range ba.bootstraps {
		if err := fn(); err != nil {
			return err
		}
	}

	return nil
}

// Execute panics - concrete actions must implement this.
func (*BaseAction) Execute(_ context.Context) error {
	panic("BaseAction.Execute called directly - concrete action must implement Execute")
}

// RegisterOutput registers an output resource on the base action and returns a Resource to embed.
// The action parameter should be the concrete action (e.g., *myAction) to preserve type identity.
// This is called by concrete action's AddOutput implementation.
//
// Example:
//
//	func (a *myAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
//	    return resource.RegisterOutput(a, a.BaseAction, name, out, copyFrom...)
//	}
func RegisterOutput(action Action, base *BaseAction, name string, out Resource, copyFrom ...Resource) Resource {
	base.outputs = append(base.outputs, out)

	res := &baseResource{
		id:         nextID(name),
		name:       name,
		producedBy: action, // Store the concrete action, not BaseAction
	}

	if len(copyFrom) > 0 && copyFrom[0] != nil {
		source := copyFrom[0]

		base.bootstraps = append(base.bootstraps, func() error {
			return source.Copy(out)
		})
	}

	return res
}
