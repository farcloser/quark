package resource_test

import (
	"context"
	"errors"
	"testing"

	"github.com/farcloser/quark/pkg/fault"
	"github.com/farcloser/quark/pkg/sys/resource"
)

// testResource is a concrete resource for testing.
type testResource struct {
	resource.Resource

	Value string
}

func (tr *testResource) Copy(dest resource.Resource) error {
	if d, ok := dest.(*testResource); ok {
		d.Value = tr.Value

		return nil
	}

	return errors.New("incompatible resource type")
}

// testAction is a concrete action for testing.
type testAction struct {
	*resource.BaseAction

	executed bool
}

func (ta *testAction) Execute(_ context.Context) error {
	ta.executed = true

	return nil
}

func (ta *testAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(ta, ta.BaseAction, name, out, copyFrom...)
}

func TestNewAction(t *testing.T) {
	t.Parallel()

	action := resource.NewAction("test-action")

	if action.NodeName() != "test-action" {
		t.Errorf("NodeName() = %q, want %q", action.NodeName(), "test-action")
	}

	if action.NodeID() == "" {
		t.Error("NodeID() should not be empty")
	}

	if len(action.Dependencies()) != 0 {
		t.Errorf("Dependencies() = %d, want 0", len(action.Dependencies()))
	}

	if len(action.Outputs()) != 0 {
		t.Errorf("Outputs() = %d, want 0", len(action.Outputs()))
	}
}

func TestNewAction_WithDependencies(t *testing.T) {
	t.Parallel()

	// Create a producing action and resource first
	producer := &testAction{BaseAction: resource.NewAction("producer")}
	dep := &testResource{}
	dep.Resource = producer.AddOutput("dep", dep)

	// Create action with dependency
	action := resource.NewAction("consumer", dep)

	deps := action.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("Dependencies() = %d, want 1", len(deps))
	}

	if deps[0] != dep {
		t.Error("Dependencies()[0] should be the registered dependency")
	}
}

func TestBaseAction_UniqueIDs(t *testing.T) {
	t.Parallel()

	action1 := resource.NewAction("action")
	action2 := resource.NewAction("action")

	if action1.NodeID() == action2.NodeID() {
		t.Error("Two actions with same name should have different IDs")
	}
}

func TestBaseAction_ExecutePanics(t *testing.T) {
	t.Parallel()

	action := resource.NewAction("test")

	defer func() {
		if r := recover(); r == nil {
			t.Error("BaseAction.Execute should panic")
		}
	}()

	_ = action.Execute(context.Background())
}

func TestBaseAction_Bootstrap(t *testing.T) {
	t.Parallel()

	action := resource.NewAction("test")

	// Bootstrap with no functions should succeed
	if err := action.Bootstrap(); err != nil {
		t.Errorf("Bootstrap() with no functions = %v, want nil", err)
	}
}

func TestRegisterOutput(t *testing.T) {
	t.Parallel()

	action := &testAction{BaseAction: resource.NewAction("producer")}
	output := &testResource{Value: "output"}

	res := action.AddOutput("my-output", output)

	// Check outputs registered
	outputs := action.Outputs()
	if len(outputs) != 1 {
		t.Fatalf("Outputs() = %d, want 1", len(outputs))
	}

	if outputs[0] != output {
		t.Error("Outputs()[0] should be the registered output")
	}

	// Check resource properties
	if res.NodeName() != "my-output" {
		t.Errorf("NodeName() = %q, want %q", res.NodeName(), "my-output")
	}

	if res.NodeID() == "" {
		t.Error("NodeID() should not be empty")
	}

	if res.NodeParent() != action {
		t.Error("NodeParent() should be the producing action")
	}
}

func TestRegisterOutput_WithCopyFrom(t *testing.T) {
	t.Parallel()

	action := &testAction{BaseAction: resource.NewAction("producer")}
	source := &testResource{Value: "source-value"}
	dest := &testResource{}

	_ = action.AddOutput("output", dest, source)

	// Before bootstrap, dest should be empty
	if dest.Value != "" {
		t.Errorf("dest.Value before bootstrap = %q, want empty", dest.Value)
	}

	// Run bootstrap
	if err := action.Bootstrap(); err != nil {
		t.Fatalf("Bootstrap() = %v, want nil", err)
	}

	// After bootstrap, dest should have source's value
	if dest.Value != "source-value" {
		t.Errorf("dest.Value after bootstrap = %q, want %q", dest.Value, "source-value")
	}
}

func TestBaseResource_CopyReturnsError(t *testing.T) {
	t.Parallel()

	action := &testAction{BaseAction: resource.NewAction("producer")}
	output := &testResource{}
	res := action.AddOutput("output", output)

	// The base resource's Copy method should return ErrNotImplemented
	err := res.Copy(output)
	if err == nil {
		t.Error("baseResource.Copy() should return error")
	}

	if !errors.Is(err, fault.ErrNotImplemented) {
		t.Errorf("Copy() error = %v, want %v", err, fault.ErrNotImplemented)
	}
}

func TestConcreteAction_Execute(t *testing.T) {
	t.Parallel()

	action := &testAction{BaseAction: resource.NewAction("test")}

	if action.executed {
		t.Error("executed should be false before Execute")
	}

	if err := action.Execute(context.Background()); err != nil {
		t.Errorf("Execute() = %v, want nil", err)
	}

	if !action.executed {
		t.Error("executed should be true after Execute")
	}
}

func TestNewWithAction(t *testing.T) {
	t.Parallel()

	// Create source resource
	producer := &testAction{BaseAction: resource.NewAction("producer")}
	source := &testResource{Value: "source"}
	source.Resource = producer.AddOutput("source", source)

	// Create additional dependency
	depProducer := &testAction{BaseAction: resource.NewAction("dep-producer")}
	dep := &testResource{}
	dep.Resource = depProducer.AddOutput("dep", dep)

	// Create with action
	withAction := resource.NewWithAction("with", source, dep)

	if withAction.NodeName() != "with" {
		t.Errorf("NodeName() = %q, want %q", withAction.NodeName(), "with")
	}

	deps := withAction.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("Dependencies() = %d, want 2", len(deps))
	}

	// First dep should be source
	if deps[0] != source {
		t.Error("Dependencies()[0] should be source")
	}

	// Second dep should be additional dep
	if deps[1] != dep {
		t.Error("Dependencies()[1] should be additional dep")
	}
}

func TestWithAction_Execute(t *testing.T) {
	t.Parallel()

	producer := &testAction{BaseAction: resource.NewAction("producer")}
	source := &testResource{}
	source.Resource = producer.AddOutput("source", source)

	withAction := resource.NewWithAction("with", source)

	// Execute should be a no-op and return nil
	if err := withAction.Execute(context.Background()); err != nil {
		t.Errorf("Execute() = %v, want nil", err)
	}
}
