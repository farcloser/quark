package resource

import (
	"context"
	"fmt"
	"sync/atomic"
)

// Resource interface - only what Plan needs for execution.
// DependsOn is not part of the interface; each concrete type provides its own typed version.
// Consumers can implement custom resources by embedding BaseResource[T].
type Resource interface {
	ResourceID() string
	ResourceName() string
	ResourceDeps() []Resource
	Execute(ctx context.Context) error
}

// idGenerator provides unique IDs for resources.
//
//nolint:gochecknoglobals
var idGenerator atomic.Uint64

// nextID generates a unique ID with the given prefix.
// Use this when creating custom resources.
func nextID(prefix string) string {
	seq := idGenerator.Add(1)

	return fmt.Sprintf("%s-%d", prefix, seq)
}

// BaseResource provides common dependency tracking for all resources.
// Generic over T to enable DependsOn to return the concrete type.
// Use NewBaseResource to create instances.
//
// Example:
//
//	type MyResource struct {
//	    sdk.BaseResource[MyResource]
//	    // custom fields
//	}
//
//	func NewMyResource() *MyResource {
//	    r := &MyResource{}
//	    r.BaseResource = sdk.NewBaseResource(r, "myresource")
//	    return r
//	}
type BaseResource[T any] struct {
	self *T
	id   string
	name string
	deps []Resource
}

// NewBaseResource creates a new BaseResource with the given name.
// The name is used both as the ID prefix and display name.
func NewBaseResource[T any](self *T, name string) BaseResource[T] {
	return BaseResource[T]{
		self: self,
		id:   nextID(name),
		name: name,
	}
}

// DependsOn adds a dependency and returns the concrete type for chaining.
func (br *BaseResource[T]) DependsOn(res Resource) *T {
	br.deps = append(br.deps, res)

	return br.self
}

// ResourceID implements Resource.
func (br *BaseResource[T]) ResourceID() string {
	return br.id
}

// ResourceName implements Resource.
func (br *BaseResource[T]) ResourceName() string {
	return br.name
}

// ResourceDeps implements Resource.
func (br *BaseResource[T]) ResourceDeps() []Resource {
	return br.deps
}

// Execute implements Resource. Override this in your concrete type.
func (*BaseResource[T]) Execute(_ context.Context) error {
	panic("concrete types must implement Execute(ctx context.Context)")
}
