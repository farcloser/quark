package sdk

import (
	"context"
	"log/slog"
	"sync"

	"github.com/farcloser/quark/internal/buildctl"
	"github.com/farcloser/quark/internal/builder"
	"github.com/farcloser/quark/sdk/build"
)

const logKeyNode = "node"

// Scheduler coordinates build slot allocation across nodes.
// It maintains a FIFO queue of waiting builds and dispatches them
// to available nodes based on their preferences.
//
// Each build specifies a set of acceptable nodes. When a slot frees,
// the scheduler assigns it to the first queued build that accepts that node.
//
// The scheduler also manages socket lifecycle: sockets are kept alive
// while builds are active OR pending builds want that node. Sockets are
// closed when no longer needed.
type Scheduler struct {
	mu      sync.Mutex
	nodes   map[string]*nodeSlots // keyed by node.NodeID()
	waiters []*slotWaiter         // FIFO queue of waiting builds
	log     *slog.Logger
}

// nodeSlots tracks capacity and socket for a single node.
type nodeSlots struct {
	node     *Node
	sentinel builder.Client // keeps socket alive while needed
	active   int            // number of active builds
	capacity int            // max concurrent builds
}

// slotWaiter represents a build waiting for a node slot.
type slotWaiter struct {
	acceptable map[string]bool // set of acceptable node IDs
	assigned   chan *Node      // receives assigned node (buffered, size 1)
}

// defaultScheduler is the package-level scheduler instance.
//
//nolint:gochecknoglobals // singleton pattern for cross-build coordination
var defaultScheduler = &Scheduler{
	nodes: make(map[string]*nodeSlots),
	log:   slog.Default(),
}

// Acquire blocks until a slot is available on one of the acceptable nodes.
// Returns the assigned node or an error if the context is cancelled.
// The caller MUST call Release() when done with the node.
func (s *Scheduler) Acquire(ctx context.Context, nodes []*Node) (*Node, error) {
	if len(nodes) == 0 {
		return nil, build.ErrNodeRequired
	}

	s.mu.Lock()

	// Build set of acceptable node IDs
	acceptable := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		nodeID := node.NodeID()
		acceptable[nodeID] = true
		s.log.Debug("acquire: acceptable node",
			logKeyNode, node.Moniker(),
			"node_id", nodeID)
	}

	// Try immediate assignment - check each acceptable node for capacity
	for _, node := range nodes {
		nodeID := node.NodeID()
		slots, exists := s.nodes[nodeID]

		if !exists {
			continue // node not registered yet
		}

		if slots.active < slots.capacity {
			// Ensure socket exists before incrementing active
			if err := s.ensureSocket(ctx, slots); err != nil {
				s.mu.Unlock()

				return nil, err
			}

			slots.active++
			s.log.Debug("acquired node slot",
				logKeyNode, slots.node.Moniker(),
				"active", slots.active,
				"capacity", slots.capacity)
			s.mu.Unlock()

			// Return the REGISTERED node to ensure consistent NodeID
			return slots.node, nil
		}
	}

	// No immediate slot available - queue and wait
	waiter := &slotWaiter{
		acceptable: acceptable,
		assigned:   make(chan *Node, 1),
	}
	s.waiters = append(s.waiters, waiter)

	// Ensure sockets exist for all acceptable nodes (pending builds need them)
	for _, node := range nodes {
		if slots, exists := s.nodes[node.NodeID()]; exists {
			if err := s.ensureSocket(ctx, slots); err != nil {
				// Remove waiter on error
				s.removeWaiterLocked(waiter)
				s.mu.Unlock()

				return nil, err
			}
		}
	}

	// Log warning with capacity details
	s.logCapacityWarning(ctx, nodes)
	s.mu.Unlock()

	// Wait for assignment or cancellation
	select {
	case node := <-waiter.assigned:
		return node, nil
	case <-ctx.Done():
		s.cancelWaiter(waiter)

		return nil, ctx.Err() //nolint:wrapcheck // context errors are self-explanatory
	}
}

// Release frees a slot on the node and wakes the next compatible waiter.
// Must be called exactly once for each successful Acquire().
func (s *Scheduler) Release(node *Node) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nodeID := node.NodeID()
	slots, exists := s.nodes[nodeID]

	s.log.Info("release called",
		logKeyNode, node.Moniker(),
		"node_id", nodeID,
		"exists", exists,
		"waiters", len(s.waiters))

	if !exists {
		s.log.Warn("release: node not registered",
			logKeyNode, node.Moniker(),
			"node_id", nodeID)

		return
	}

	if slots.active <= 0 {
		s.log.Warn("release: already at zero",
			logKeyNode, node.Moniker(),
			"active", slots.active)

		return
	}

	slots.active--
	s.log.Debug("released node slot",
		logKeyNode, node.Moniker(),
		"active", slots.active,
		"capacity", slots.capacity)

	// Find first waiter that accepts this node
	for idx, waiter := range s.waiters {
		// Debug: log what we're checking
		s.log.Debug("checking waiter",
			"waiter_index", idx,
			"node_id", nodeID,
			"acceptable_count", len(waiter.acceptable),
			"accepts_this_node", waiter.acceptable[nodeID])

		if waiter.acceptable[nodeID] {
			// Assign this node to the waiter
			slots.active++

			waiter.assigned <- node

			// Remove waiter from queue
			s.waiters = append(s.waiters[:idx], s.waiters[idx+1:]...)

			s.log.Info("assigned queued build to node",
				logKeyNode, node.Moniker(),
				"remaining_waiters", len(s.waiters))

			return
		}
	}

	s.log.Debug("no waiter wants this node",
		logKeyNode, node.Moniker(),
		"waiters_checked", len(s.waiters))

	// No waiter wants this node - check if we can close socket
	s.maybeCloseSocket(slots)
}

// Active returns the number of builds currently running on a node.
func (s *Scheduler) Active(node *Node) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if slots, exists := s.nodes[node.NodeID()]; exists {
		return slots.active
	}

	return 0
}

// Available returns the number of available slots on a node.
func (s *Scheduler) Available(node *Node) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	if slots, exists := s.nodes[node.NodeID()]; exists {
		return slots.capacity - slots.active
	}

	return 0
}

// logCapacityWarning logs details about node capacity when a build must wait.
// Caller must hold s.mu.
func (s *Scheduler) logCapacityWarning(ctx context.Context, requestedNodes []*Node) {
	// Build capacity details for each requested node
	var nodeDetails []any

	for _, node := range requestedNodes {
		if slots, exists := s.nodes[node.NodeID()]; exists {
			nodeDetails = append(nodeDetails,
				slog.Group(node.Moniker(),
					slog.Int("active", slots.active),
					slog.Int("capacity", slots.capacity),
				),
			)
		}
	}

	s.log.WarnContext(ctx, "all build nodes at capacity, waiting for available slot",
		slog.Int("requested_nodes", len(requestedNodes)),
		slog.Int("queue_position", len(s.waiters)),
		slog.Int("total_waiting", len(s.waiters)),
		slog.Group("node_capacity", nodeDetails...),
	)
}

// registerNode adds a node to the scheduler's tracking.
// Called when a node is created. Thread-safe.
func (s *Scheduler) registerNode(node *Node, capacity int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nodeID := node.NodeID()
	if _, exists := s.nodes[nodeID]; !exists {
		s.nodes[nodeID] = &nodeSlots{
			node:     node,
			capacity: capacity,
		}
	}
}

// ensureSocket creates a sentinel client for the node if one doesn't exist.
// Caller must hold s.mu.
func (s *Scheduler) ensureSocket(ctx context.Context, slots *nodeSlots) error {
	if slots.sentinel != nil {
		return nil // socket already exists
	}

	client, err := buildctl.NewClient(
		ctx,
		slots.node.Connection(),
		s.log.With("sentinel", true),
	)
	if err != nil {
		return err //nolint:wrapcheck // caller adds context
	}

	slots.sentinel = client
	s.log.Debug("created socket for node", logKeyNode, slots.node.Moniker())

	return nil
}

// maybeCloseSocket closes the sentinel client if the socket is no longer needed.
// A socket is no longer needed when: active == 0 AND no pending waiter wants this node.
// Caller must hold s.mu.
func (s *Scheduler) maybeCloseSocket(slots *nodeSlots) {
	if slots.sentinel == nil {
		return // no socket to close
	}

	if slots.active > 0 {
		return // still in use
	}

	// Check if any pending waiter wants this node
	nodeID := slots.node.NodeID()
	for _, waiter := range s.waiters {
		if waiter.acceptable[nodeID] {
			return // pending build wants this node
		}
	}

	// No active builds and no pending waiters want this node - close socket
	if err := slots.sentinel.Close(); err != nil {
		s.log.Warn("failed to close sentinel client", logKeyNode, slots.node.Moniker(), "error", err)
	}

	slots.sentinel = nil
	s.log.Debug("closed socket for node", logKeyNode, slots.node.Moniker())
}

// cancelWaiter removes a waiter from the queue when its context is cancelled.
func (s *Scheduler) cancelWaiter(waiter *slotWaiter) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.removeWaiterLocked(waiter)

	// Check if any sockets can be closed now that this waiter is gone
	for _, slots := range s.nodes {
		s.maybeCloseSocket(slots)
	}
}

// removeWaiterLocked removes a waiter from the queue.
// Caller must hold s.mu.
func (s *Scheduler) removeWaiterLocked(target *slotWaiter) {
	for idx, waiter := range s.waiters {
		if waiter == target {
			s.waiters = append(s.waiters[:idx], s.waiters[idx+1:]...)

			return
		}
	}
}
