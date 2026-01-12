package dag_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/farcloser/quark/dev/dag"
)

// errTaskFailed is a static error for test assertions.
var errTaskFailed = errors.New("task failed")

// mockTask implements Executable for testing.
type mockTask struct {
	name     string
	duration time.Duration
	err      error
	executed atomic.Bool
	order    *[]string
	orderMu  *sync.Mutex
}

func (m *mockTask) Execute(ctx context.Context) error {
	if m.duration > 0 {
		select {
		case <-time.After(m.duration):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.err != nil {
		return m.err
	}

	m.executed.Store(true)

	if m.order != nil && m.orderMu != nil {
		m.orderMu.Lock()
		*m.order = append(*m.order, m.name)
		m.orderMu.Unlock()
	}

	return nil
}

func (m *mockTask) Name() string {
	return m.name
}

func TestGraph_Execute_Empty(t *testing.T) {
	t.Parallel()

	g := dag.NewGraph[*mockTask]()

	if err := g.Execute(t.Context()); err != nil {
		t.Errorf("Execute() on empty graph returned error: %v", err)
	}
}

func TestGraph_Execute_SingleNode(t *testing.T) {
	t.Parallel()

	task := &mockTask{name: "task1"}
	node := dag.NewNode("1", task)

	g := dag.NewGraph[*mockTask]()
	g.Add(node)

	err := g.Execute(t.Context())
	if err != nil {
		t.Errorf("Execute() returned error: %v", err)
	}

	if !task.executed.Load() {
		t.Error("task was not executed")
	}
}

func TestGraph_Execute_LinearChain(t *testing.T) {
	t.Parallel()

	var order []string

	var mu sync.Mutex

	task1 := &mockTask{name: "task1", duration: 10 * time.Millisecond, order: &order, orderMu: &mu}
	task2 := &mockTask{name: "task2", duration: 10 * time.Millisecond, order: &order, orderMu: &mu}
	task3 := &mockTask{name: "task3", duration: 10 * time.Millisecond, order: &order, orderMu: &mu}

	node1 := dag.NewNode("1", task1)
	node2 := dag.NewNode("2", task2)
	node3 := dag.NewNode("3", task3)

	// Chain: 1 -> 2 -> 3
	node2.DependsOn(node1)
	node3.DependsOn(node2)

	g := dag.NewGraph[*mockTask]()
	g.Add(node1)
	g.Add(node2)
	g.Add(node3)

	err := g.Execute(t.Context())
	if err != nil {
		t.Errorf("Execute() returned error: %v", err)
	}

	// Verify execution order
	if len(order) != 3 {
		t.Fatalf("expected 3 tasks executed, got %d", len(order))
	}

	if order[0] != "task1" || order[1] != "task2" || order[2] != "task3" {
		t.Errorf("expected order [task1, task2, task3], got %v", order)
	}
}

func TestGraph_Execute_Parallel(t *testing.T) {
	t.Parallel()

	task1 := &mockTask{name: "task1", duration: 50 * time.Millisecond}
	task2 := &mockTask{name: "task2", duration: 50 * time.Millisecond}
	task3 := &mockTask{name: "task3", duration: 50 * time.Millisecond}

	node1 := dag.NewNode("1", task1)
	node2 := dag.NewNode("2", task2)
	node3 := dag.NewNode("3", task3)

	// No dependencies - all should run in parallel

	g := dag.NewGraph[*mockTask]()
	g.Add(node1)
	g.Add(node2)
	g.Add(node3)

	start := time.Now()
	err := g.Execute(t.Context())
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Execute() returned error: %v", err)
	}

	// If parallel, should complete in ~50ms, not 150ms
	if elapsed > 100*time.Millisecond {
		t.Errorf("expected parallel execution (~50ms), took %v", elapsed)
	}
}

func TestGraph_Execute_DiamondDependency(t *testing.T) {
	t.Parallel()

	var order []string

	var mu sync.Mutex

	//     A
	//    / \
	//   B   C
	//    \ /
	//     D

	taskA := &mockTask{name: "A", duration: 10 * time.Millisecond, order: &order, orderMu: &mu}
	taskB := &mockTask{name: "B", duration: 10 * time.Millisecond, order: &order, orderMu: &mu}
	taskC := &mockTask{name: "C", duration: 10 * time.Millisecond, order: &order, orderMu: &mu}
	taskD := &mockTask{name: "D", duration: 10 * time.Millisecond, order: &order, orderMu: &mu}

	nodeA := dag.NewNode("A", taskA)
	nodeB := dag.NewNode("B", taskB)
	nodeC := dag.NewNode("C", taskC)
	nodeD := dag.NewNode("D", taskD)

	nodeB.DependsOn(nodeA)
	nodeC.DependsOn(nodeA)
	nodeD.DependsOn(nodeB, nodeC)

	g := dag.NewGraph[*mockTask]()
	g.Add(nodeA)
	g.Add(nodeB)
	g.Add(nodeC)
	g.Add(nodeD)

	err := g.Execute(t.Context())
	if err != nil {
		t.Errorf("Execute() returned error: %v", err)
	}

	// A must be first, D must be last
	if order[0] != "A" {
		t.Errorf("expected A first, got %s", order[0])
	}

	if order[3] != "D" {
		t.Errorf("expected D last, got %s", order[3])
	}
}

func TestGraph_Execute_Error(t *testing.T) {
	t.Parallel()

	task1 := &mockTask{name: "task1"}
	task2 := &mockTask{name: "task2", err: errTaskFailed}
	task3 := &mockTask{name: "task3"}

	node1 := dag.NewNode("1", task1)
	node2 := dag.NewNode("2", task2)
	node3 := dag.NewNode("3", task3)

	node2.DependsOn(node1)
	node3.DependsOn(node2)

	g := dag.NewGraph[*mockTask]()
	g.Add(node1)
	g.Add(node2)
	g.Add(node3)

	err := g.Execute(t.Context())
	if err == nil {
		t.Error("Execute() should have returned error")
	}

	if !errors.Is(err, errTaskFailed) {
		t.Errorf("expected error to wrap %v, got %v", errTaskFailed, err)
	}

	// task3 should not have executed due to dependency failure
	if task3.executed.Load() {
		t.Error("task3 should not have executed after task2 failed")
	}
}

func TestGraph_Execute_CycleDetection(t *testing.T) {
	t.Parallel()

	task1 := &mockTask{name: "task1"}
	task2 := &mockTask{name: "task2"}
	task3 := &mockTask{name: "task3"}

	node1 := dag.NewNode("1", task1)
	node2 := dag.NewNode("2", task2)
	node3 := dag.NewNode("3", task3)

	// Create cycle: 1 -> 2 -> 3 -> 1
	node2.DependsOn(node1)
	node3.DependsOn(node2)
	node1.DependsOn(node3)

	g := dag.NewGraph[*mockTask]()
	g.Add(node1)
	g.Add(node2)
	g.Add(node3)

	err := g.Execute(t.Context())

	if !errors.Is(err, dag.ErrCycleDetected) {
		t.Errorf("expected ErrCycleDetected, got %v", err)
	}
}

func TestGraph_Execute_ContextCancellation(t *testing.T) {
	t.Parallel()

	task1 := &mockTask{name: "task1", duration: 500 * time.Millisecond}

	node1 := dag.NewNode("1", task1)

	g := dag.NewGraph[*mockTask]()
	g.Add(node1)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	err := g.Execute(ctx)
	if err == nil {
		t.Error("Execute() should have returned error on context cancellation")
	}
}
