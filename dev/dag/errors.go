package dag

import "errors"

// ErrCycleDetected is returned when a cycle is detected in the graph.
var ErrCycleDetected = errors.New("cycle detected in dependency graph")
