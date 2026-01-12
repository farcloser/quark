package sdk

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"

	"github.com/farcloser/quark/dev/dag"
	"github.com/farcloser/quark/dev/resource"
)

const (
	debugGraphEnvVar = "QUARK_DEBUG_GRAPH"
	traceEnvVar      = "QUARK_TRACE"
)

// Plan collects resources and executes their producing actions respecting dependencies.
type Plan struct {
	resources []resource.Resource
}

// NewPlan creates a new empty plan.
func NewPlan() *Plan {
	return &Plan{}
}

// Add adds resources to the plan.
// Their producing actions and all dependencies are auto-discovered during execution.
func (plan *Plan) Add(resources ...resource.Resource) {
	plan.resources = append(plan.resources, resources...)
}

// Execute runs all actions in the plan respecting dependencies.
// Independent actions run in parallel.
// If QUARK_DEBUG_GRAPH env var is set, exports DOT graph to stdout instead of executing.
// If QUARK_TRACE env var is set to a file path, generates a waterfall trace DOT file.
func (plan *Plan) Execute(ctx context.Context) error {
	// Check for debug mode
	if os.Getenv(debugGraphEnvVar) != "" {
		return plan.ExportDOT(os.Stdout)
	}

	tracePath := os.Getenv(traceEnvVar)

	// Discover all actions and build execution graph
	discovered, resourceToAction := plan.discoverAllActions()

	// Build DAG of actions
	execGraph := dag.NewGraph[*actionWrapper]()
	nodes := make(map[string]*dag.Node[*actionWrapper])

	// Create nodes for all discovered actions
	for id, action := range discovered {
		wrapper := &actionWrapper{action: action}
		node := dag.NewNode(id, wrapper)
		nodes[id] = node
		execGraph.Add(node)
	}

	// Wire up dependencies
	for id, action := range discovered {
		node := nodes[id]

		for _, dep := range action.Dependencies() {
			if producingAction, ok := resourceToAction[dep.NodeID()]; ok {
				if depNode, ok := nodes[producingAction.NodeID()]; ok {
					node.DependsOn(depNode)
				}
			}
		}
	}

	// Execute the graph with trace collection
	traces, execErr := execGraph.ExecuteWithTrace(ctx)

	// Generate trace file if requested (even if execution succeeded)
	if tracePath != "" && len(traces) > 0 {
		if err := plan.exportTraceWaterfall(tracePath, traces); err != nil {
			// Log but don't fail on trace export error
			fmt.Fprintf(os.Stderr, "warning: failed to export trace: %v\n", err)
		}
	}

	if execErr != nil {
		return fmt.Errorf("%w: %w", ErrPlanExecutionFailed, execErr)
	}

	return nil
}

// ExportDOT writes the plan's dependency graph in DOT format.
// Pipe to `dot -Tsvg` to generate SVG: quark debug --plan ./myplan | dot -Tsvg > graph.svg.
func (plan *Plan) ExportDOT(writer io.Writer) error {
	discovered, resourceToAction := plan.discoverAllActions()

	// Build graph using dominikbraun/graph for DOT export.
	// Use NodeID as unique key, NodeName as display label.
	dotGraph := graph.New(graph.StringHash, graph.Directed())

	// Add vertices with label and color based on action type
	for actionID, action := range discovered {
		name := action.NodeName()
		label := fmt.Sprintf("%s\n(%s)", name, actionID)
		fillColor := actionFillColor(name)

		if err := dotGraph.AddVertex(actionID,
			graph.VertexAttribute("label", label),
			graph.VertexAttribute("style", "filled"),
			graph.VertexAttribute("fillcolor", fillColor),
		); err != nil {
			return fmt.Errorf("failed to add vertex %s: %w", actionID, err)
		}
	}

	// Add edges (dependency -> dependent)
	for actionID, action := range discovered {
		for _, dep := range action.Dependencies() {
			if producingAction, ok := resourceToAction[dep.NodeID()]; ok {
				sourceID := producingAction.NodeID()
				sourceName := producingAction.NodeName()

				// Style edges from create nodes as green and bold
				var edgeOpts []func(*graph.EdgeProperties)
				if strings.HasPrefix(sourceName, "create:") {
					edgeOpts = append(edgeOpts,
						graph.EdgeAttribute("color", "darkgreen"),
						graph.EdgeAttribute("style", "bold"),
						graph.EdgeAttribute("penwidth", "2.0"),
					)
				}

				if err := dotGraph.AddEdge(sourceID, actionID, edgeOpts...); err != nil {
					return fmt.Errorf("failed to add edge %s -> %s: %w", sourceID, actionID, err)
				}
			}
		}
	}

	// Export as DOT with increased vertical spacing (ranksep default is 0.5)
	if err := draw.DOT(dotGraph, writer, draw.GraphAttribute("ranksep", "1.5")); err != nil {
		return fmt.Errorf("failed to export DOT: %w", err)
	}

	return nil
}

// discoverAllActions discovers all actions in the plan and returns maps for building the graph.
func (plan *Plan) discoverAllActions() (map[string]resource.Action, map[string]resource.Action) {
	discovered := make(map[string]resource.Action)
	resourceToAction := make(map[string]resource.Action)

	for _, res := range plan.resources {
		if action := res.NodeParent(); action != nil {
			plan.discoverActions(action, discovered, resourceToAction)
		}
	}

	return discovered, resourceToAction
}

// discoverActions recursively discovers all actions through deps.
func (plan *Plan) discoverActions(
	action resource.Action,
	discovered map[string]resource.Action,
	resourceToAction map[string]resource.Action,
) {
	actionID := action.NodeID()
	if _, seen := discovered[actionID]; seen {
		return
	}

	discovered[actionID] = action

	// Map outputs to this action (for DAG wiring later)
	for _, output := range action.Outputs() {
		resourceToAction[output.NodeID()] = action
	}

	// Discover actions that produce our deps
	for _, dep := range action.Dependencies() {
		if producingAction := dep.NodeParent(); producingAction != nil {
			plan.discoverActions(producingAction, discovered, resourceToAction)
		}
	}
}

// actionFillColor returns a fill color for DOT graph based on action name prefix.
func actionFillColor(name string) string {
	switch {
	case strings.HasPrefix(name, "create:"):
		return "lightgreen"
	case strings.HasPrefix(name, "build:"):
		return "lightblue"
	case strings.HasPrefix(name, "check:"):
		return "gold"
	case strings.HasPrefix(name, "audit:"):
		return "plum"
	case strings.HasPrefix(name, "scan:"):
		return "lightsalmon"
	case strings.HasPrefix(name, "log:"):
		return "lightgray"
	case strings.HasPrefix(name, "sign:"):
		return "lightcyan"
	case strings.HasPrefix(name, "attest:"):
		return "lavender"
	default:
		return "white"
	}
}

// actionWrapper adapts an Action to the dag.Executable interface.
type actionWrapper struct {
	action resource.Action
}

func (w *actionWrapper) Execute(ctx context.Context) error {
	if err := w.action.Bootstrap(); err != nil {
		return err //nolint:wrapcheck // pure delegation, action wraps its own errors
	}

	return w.action.Execute(ctx) //nolint:wrapcheck // pure delegation, action wraps its own errors
}

func (w *actionWrapper) Name() string {
	return w.action.NodeName()
}

// exportTraceWaterfall generates an SVG file showing execution timing as a waterfall chart.
// Horizontal axis is time, each node is a rectangle from start to end time.
// Nodes are ordered vertically by dependency order.
func (*Plan) exportTraceWaterfall(path string, traces []dag.TraceEntry) error {
	if len(traces) == 0 {
		return nil
	}

	// Find the earliest start time as baseline
	var minStart time.Time

	for i, trace := range traces {
		if i == 0 || trace.Start.Before(minStart) {
			minStart = trace.Start
		}
	}

	// Sort traces by dependency order using topological sort
	sortedTraces := sortTracesByDependencyOrder(traces)

	// Find total duration
	var maxEnd time.Time

	for _, trace := range traces {
		if trace.End.After(maxEnd) {
			maxEnd = trace.End
		}
	}

	totalDuration := maxEnd.Sub(minStart)
	if totalDuration == 0 {
		totalDuration = time.Second
	}

	const (
		chartWidth  = 1200.0
		labelWidth  = 350.0
		rowHeight   = 25.0
		barHeight   = 20.0
		topMargin   = 40.0
		minBarWidth = 2.0
	)

	barAreaWidth := chartWidth - labelWidth - 20
	totalHeight := topMargin + float64(len(sortedTraces))*rowHeight + 20

	// Create SVG file
	file, err := os.Create(path) //nolint:gosec // path is from trusted env var
	if err != nil {
		return fmt.Errorf("failed to create trace file: %w", err)
	}
	defer file.Close()

	// SVG header
	_, _ = fmt.Fprintf(file, `<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%.0f">
<style>
  .label { font: 11px monospace; fill: #333; }
  .time { font: 10px monospace; fill: #666; }
  .header { font: bold 12px sans-serif; fill: #333; }
</style>
<rect width="100%%" height="100%%" fill="white"/>
`, chartWidth, totalHeight)

	// Header
	_, _ = fmt.Fprintf(file, `<text x="10" y="20" class="header">Execution Trace (total: %.2fs)</text>
`, totalDuration.Seconds())

	// Draw bars
	for idx, trace := range sortedTraces {
		yPos := topMargin + float64(idx)*rowHeight
		startOffset := trace.Start.Sub(minStart)
		duration := trace.Duration

		xStart := labelWidth + (float64(startOffset.Milliseconds())/float64(totalDuration.Milliseconds()))*barAreaWidth
		barWidth := (float64(duration.Milliseconds()) / float64(totalDuration.Milliseconds())) * barAreaWidth

		if barWidth < minBarWidth {
			barWidth = minBarWidth
		}

		fillColor := actionFillColor(trace.NodeName)

		// Label
		_, _ = fmt.Fprintf(file, `<text x="5" y="%.1f" class="label">%s</text>
`, yPos+barHeight/2+4, escapeXML(trace.NodeName))

		// Bar
		_, _ = fmt.Fprintf(
			file,
			`<rect x="%.1f" y="%.1f" width="%.1f" height="%.0f" fill="%s" stroke="#666" stroke-width="0.5"/>
`,
			xStart,
			yPos,
			barWidth,
			barHeight,
			fillColor,
		)

		// Duration text
		_, _ = fmt.Fprintf(file, `<text x="%.1f" y="%.1f" class="time">%.2fs</text>
`, xStart+barWidth+5, yPos+barHeight/2+4, duration.Seconds())
	}

	_, _ = fmt.Fprint(file, "</svg>\n")

	return nil
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")

	return s
}

// sortTracesByDependencyOrder sorts traces so that dependencies come before dependents.
func sortTracesByDependencyOrder(traces []dag.TraceEntry) []dag.TraceEntry {
	// Build dependency map
	depMap := make(map[string][]string)
	traceMap := make(map[string]dag.TraceEntry)

	for _, trace := range traces {
		depMap[trace.NodeID] = trace.Deps
		traceMap[trace.NodeID] = trace
	}

	// Topological sort using Kahn's algorithm
	inDegree := make(map[string]int)
	for nodeID := range traceMap {
		inDegree[nodeID] = 0
	}

	for _, trace := range traces {
		for _, dep := range trace.Deps {
			if _, exists := traceMap[dep]; exists {
				inDegree[trace.NodeID]++
			}
		}
	}

	// Start with nodes that have no dependencies
	var queue []string

	for nodeID, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, nodeID)
		}
	}

	// Sort queue for deterministic output
	sort.Strings(queue)

	var sorted []dag.TraceEntry

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		sorted = append(sorted, traceMap[current])

		// Find nodes that depend on current
		var nextNodes []string

		for nodeID, deps := range depMap {
			if slices.Contains(deps, current) {
				inDegree[nodeID]--

				if inDegree[nodeID] == 0 {
					nextNodes = append(nextNodes, nodeID)
				}
			}
		}

		// Sort for deterministic output
		sort.Strings(nextNodes)
		queue = append(queue, nextNodes...)
	}

	return sorted
}
