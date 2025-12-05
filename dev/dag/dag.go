package dag

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrCycleDetected is returned when a cycle is detected in the graph.
var ErrCycleDetected = errors.New("cycle detected in dependency graph")

// Executable is the interface that nodes must implement to be executed.
type Executable interface {
	Execute(ctx context.Context) error
	Name() string
}

// Node wraps an executable with its dependencies.
type Node[T Executable] struct {
	id       string
	exec     T
	deps     []*Node[T]
	executed bool
	err      error
	mu       sync.Mutex
	done     chan struct{}
}

// NewNode creates a new node wrapping an executable.
func NewNode[T Executable](id string, exec T) *Node[T] {
	return &Node[T]{
		id:   id,
		exec: exec,
		done: make(chan struct{}),
	}
}

// ID returns the node's unique identifier.
func (n *Node[T]) ID() string {
	return n.id
}

// Executable returns the wrapped executable.
func (n *Node[T]) Executable() T {
	return n.exec
}

// DependsOn adds dependencies to this node.
func (n *Node[T]) DependsOn(deps ...*Node[T]) *Node[T] {
	n.deps = append(n.deps, deps...)

	return n
}

// Done returns a channel that closes when the node completes execution.
func (n *Node[T]) Done() <-chan struct{} {
	return n.done
}

// Err returns the error from execution, if any.
func (n *Node[T]) Err() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.err
}

// Graph manages nodes and their dependencies.
type Graph[T Executable] struct {
	nodes map[string]*Node[T]
	mu    sync.RWMutex
}

// NewGraph creates a new empty graph.
func NewGraph[T Executable]() *Graph[T] {
	return &Graph[T]{
		nodes: make(map[string]*Node[T]),
	}
}

// Add adds a node to the graph.
func (g *Graph[T]) Add(node *Node[T]) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.nodes[node.id] = node
}

// Get retrieves a node by ID.
func (g *Graph[T]) Get(id string) (*Node[T], bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	node, ok := g.nodes[id]

	return node, ok
}

// Nodes returns all nodes in the graph.
func (g *Graph[T]) Nodes() []*Node[T] {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*Node[T], 0, len(g.nodes))
	for _, node := range g.nodes {
		nodes = append(nodes, node)
	}

	return nodes
}

// detectCycle checks if adding dependencies would create a cycle.
func (g *Graph[T]) detectCycle() error {
	// Use Kahn's algorithm to detect cycles
	inDegree := make(map[string]int)
	for id := range g.nodes {
		inDegree[id] = 0
	}

	for _, node := range g.nodes {
		for _, dep := range node.deps {
			inDegree[node.id]++
			_ = dep // just counting incoming edges
		}
	}

	// Actually count properly - inDegree[node] = number of deps that node has
	for id := range g.nodes {
		inDegree[id] = len(g.nodes[id].deps)
	}

	queue := make([]string, 0)

	for id, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, id)
		}
	}

	visited := 0

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		visited++

		// Find nodes that depend on current
		for id, node := range g.nodes {
			for _, dep := range node.deps {
				if dep.id == current {
					inDegree[id]--
					if inDegree[id] == 0 {
						queue = append(queue, id)
					}
				}
			}
		}
	}

	if visited != len(g.nodes) {
		return ErrCycleDetected
	}

	return nil
}

// Reverse creates a new graph with all dependency edges reversed.
// If A depends on B in the original graph, B depends on A in the reversed graph.
// The new graph contains new nodes wrapping the same executables.
// This is useful for teardown operations where dependents must be removed before dependencies.
func (g *Graph[T]) Reverse() *Graph[T] {
	g.mu.RLock()
	defer g.mu.RUnlock()

	reversed := NewGraph[T]()

	// Create new nodes for each existing node (same executable, fresh state)
	newNodes := make(map[string]*Node[T])
	for id, node := range g.nodes {
		newNodes[id] = NewNode(id, node.exec)
		reversed.Add(newNodes[id])
	}

	// Reverse dependencies: if A depends on B, make B depend on A
	for _, node := range g.nodes {
		for _, dep := range node.deps {
			// Original: node depends on dep
			// Reversed: dep depends on node
			newNodes[dep.id].DependsOn(newNodes[node.id])
		}
	}

	return reversed
}

// Execute runs all nodes in the graph respecting dependencies.
// Independent nodes run in parallel. Execution stops on first error.
func (g *Graph[T]) Execute(ctx context.Context) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.nodes) == 0 {
		return nil
	}

	// Check for cycles
	if err := g.detectCycle(); err != nil {
		return err
	}

	// Create error channel and wait group
	errCh := make(chan error, len(g.nodes))

	var waitGroup sync.WaitGroup

	// Context for cancellation on error
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start a goroutine for each node
	for _, node := range g.nodes {
		waitGroup.Add(1)

		go func(currentNode *Node[T]) {
			defer waitGroup.Done()
			defer close(currentNode.done)

			// Wait for all dependencies to complete
			for _, dep := range currentNode.deps {
				select {
				case <-execCtx.Done():
					currentNode.mu.Lock()
					currentNode.err = execCtx.Err()
					currentNode.mu.Unlock()

					return
				case <-dep.Done():
					// Check if dependency failed
					if err := dep.Err(); err != nil {
						currentNode.mu.Lock()
						currentNode.err = fmt.Errorf("dependency %s failed: %w", dep.id, err)
						currentNode.mu.Unlock()

						return
					}
				}
			}

			// Execute this node
			if err := currentNode.exec.Execute(execCtx); err != nil {
				currentNode.mu.Lock()
				currentNode.err = err
				currentNode.executed = true
				currentNode.mu.Unlock()

				errCh <- fmt.Errorf("%s: %w", currentNode.exec.Name(), err)

				cancel() // Cancel other goroutines

				return
			}

			currentNode.mu.Lock()
			currentNode.executed = true
			currentNode.mu.Unlock()
		}(node)
	}

	// Wait for completion in a separate goroutine
	go func() {
		waitGroup.Wait()
		close(errCh)
	}()

	// Return first error, if any
	for err := range errCh {
		return err
	}

	return nil
}
