package resource

import "context"

// withAction is a no-op action that creates a new resource depending on
// both the source resource and additional dependencies.
// This enables expressing ordering constraints without data flow.
type withAction struct {
	*BaseAction
}

// AddOutput implements Action.
func (wa *withAction) AddOutput(name string, out Resource, copyFrom ...Resource) Resource {
	return RegisterOutput(wa, wa.BaseAction, name, out, copyFrom...)
}

// Execute is a no-op - the action exists only for dependency ordering.
func (*withAction) Execute(_ context.Context) error {
	return nil
}

// NewWithAction creates a with action that depends on source and additional deps.
// The output resource will be a copy of source with the additional dependencies.
func NewWithAction(name string, source Resource, deps ...Resource) Action {
	// Combine source with additional deps
	allDeps := make([]Resource, 0, 1+len(deps))
	allDeps = append(allDeps, source)
	allDeps = append(allDeps, deps...)

	return &withAction{
		BaseAction: NewAction(name, allDeps...),
	}
}
