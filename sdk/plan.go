package sdk

import (
	"context"
	"fmt"

	"github.com/farcloser/quark/dev/dag"
	"github.com/farcloser/quark/dev/resource"
)

// Plan collects resources and executes them respecting dependencies.
// It auto-discovers all resources through dependency chains.
type Plan struct {
	roots []resource.Resource
}

// NewPlan creates a new empty plan.
func NewPlan() *Plan {
	return &Plan{}
}

// Add adds root resources to the plan.
// All dependencies are auto-discovered during execution.
func (plan *Plan) Add(res ...resource.Resource) {
	plan.roots = append(plan.roots, res...)
}

// Execute runs all resources in the plan respecting dependencies.
// Independent resources run in parallel.
func (plan *Plan) Execute(ctx context.Context) error {
	// Discover all resources through dependency walking
	discovered := make(map[string]resource.Resource)
	for _, root := range plan.roots {
		plan.discoverResources(root, discovered)
	}

	// Build DAG
	graph := dag.NewGraph[*executableWrapper]()
	wrappers := make(map[string]*dag.Node[*executableWrapper])

	// Create nodes for all discovered resources
	for id, res := range discovered {
		wrapper := &executableWrapper{res: res}
		node := dag.NewNode(id, wrapper)
		wrappers[id] = node
		graph.Add(node)
	}

	// Wire up dependencies
	for id, res := range discovered {
		node := wrappers[id]

		for _, dep := range res.ResourceDeps() {
			if depNode, ok := wrappers[dep.ResourceID()]; ok {
				node.DependsOn(depNode)
			}
		}
	}

	// Execute the graph
	if err := graph.Execute(ctx); err != nil {
		return fmt.Errorf("plan execution failed: %w", err)
	}

	return nil
}

// discoverResources recursively discovers all resources through dependencies.
func (plan *Plan) discoverResources(res resource.Resource, discovered map[string]resource.Resource) {
	resID := res.ResourceID()
	if _, seen := discovered[resID]; seen {
		return
	}

	discovered[resID] = res

	for _, dep := range res.ResourceDeps() {
		plan.discoverResources(dep, discovered)
	}
}

// executableWrapper adapts a Resource to the dag.Executable interface.
type executableWrapper struct {
	res resource.Resource
}

func (w *executableWrapper) Execute(ctx context.Context) error {
	return w.res.Execute(ctx)
}

func (w *executableWrapper) Name() string {
	return w.res.ResourceName()
}
