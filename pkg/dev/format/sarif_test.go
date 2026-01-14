package format_test

import (
	"encoding/json"
	"testing"

	"github.com/farcloser/quark/pkg/dev/format"
	"github.com/farcloser/quark/pkg/dev/format/sarif"
	"github.com/farcloser/quark/pkg/version"
)

func TestNewSARIFReport(t *testing.T) {
	t.Parallel()

	report := format.NewSARIFReport()

	if report == nil {
		t.Fatal("expected non-nil report")
	}

	if report.Schema == nil || *report.Schema != format.SARIFSchema {
		t.Errorf("expected schema %q", format.SARIFSchema)
	}

	if report.Version != sarif.SarifSchema210JsonVersionA210 {
		t.Error("expected version 2.1.0")
	}

	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}

	run := report.Runs[0]
	if run.Tool.Driver.Name != version.Name() {
		t.Errorf("expected driver name %q, got %q", version.Name(), run.Tool.Driver.Name)
	}

	if run.Tool.Driver.Version == nil || *run.Tool.Driver.Version != version.Version() {
		t.Errorf("expected driver version %q", version.Version())
	}

	if run.Tool.Driver.InformationUri == nil || *run.Tool.Driver.InformationUri != format.QuarkInfoURI {
		t.Errorf("expected info URI %q", format.QuarkInfoURI)
	}

	if run.Results == nil {
		t.Error("expected non-nil results slice")
	}

	if len(run.Results) != 0 {
		t.Errorf("expected empty results, got %d", len(run.Results))
	}
}

func TestNewSARIFReport_ValidJSON(t *testing.T) {
	t.Parallel()

	report := format.NewSARIFReport()

	//nolint:musttag
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal report: %v", err)
	}

	// Verify it's valid JSON by unmarshaling
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal report: %v", err)
	}

	// Check key fields exist
	if _, ok := parsed["$schema"]; !ok {
		t.Error("expected $schema field")
	}

	if _, ok := parsed["version"]; !ok {
		t.Error("expected version field")
	}

	if _, ok := parsed["runs"]; !ok {
		t.Error("expected runs field")
	}
}

func TestNewSARIFResult(t *testing.T) {
	t.Parallel()

	result := format.NewSARIFResult("RULE001", format.SARIFLevelError, "Test message")

	if result.RuleId == nil || *result.RuleId != "RULE001" {
		t.Error("expected rule ID RULE001")
	}

	if result.Level != format.SARIFLevelError {
		t.Errorf("expected level error, got %v", result.Level)
	}

	if result.Message != "Test message" {
		t.Errorf("expected message 'Test message', got %q", result.Message)
	}

	if result.Locations != nil {
		t.Error("expected nil locations for basic result")
	}
}

func TestNewSARIFResult_AllLevels(t *testing.T) {
	t.Parallel()

	levels := []sarif.ResultLevel{
		format.SARIFLevelError,
		format.SARIFLevelWarning,
		format.SARIFLevelNote,
	}

	for _, level := range levels {
		result := format.NewSARIFResult("RULE", level, "msg")
		if result.Level != level {
			t.Errorf("expected level %v, got %v", level, result.Level)
		}
	}
}

func TestNewSARIFResultWithLocation(t *testing.T) {
	t.Parallel()

	result := format.NewSARIFResultWithLocation(
		"RULE002",
		format.SARIFLevelWarning,
		"Warning message",
		"src/main.go",
		42,
	)

	if result.RuleId == nil || *result.RuleId != "RULE002" {
		t.Error("expected rule ID RULE002")
	}

	if result.Level != format.SARIFLevelWarning {
		t.Error("expected warning level")
	}

	if result.Message != "Warning message" {
		t.Error("expected warning message")
	}

	if len(result.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(result.Locations))
	}

	loc := result.Locations[0]
	if loc.PhysicalLocation == nil {
		t.Fatal("expected physical location")
	}

	// PhysicalLocation is interface{}, need to type assert to map
	physLoc, ok := loc.PhysicalLocation.(map[string]any)
	if !ok {
		t.Fatalf("expected physical location to be map[string]any, got %T", loc.PhysicalLocation)
	}

	// Check artifact location
	artifactLoc, ok := physLoc["artifactLocation"].(map[string]any)
	if !ok {
		t.Fatal("expected artifactLocation map")
	}

	if uri, ok := artifactLoc["uri"].(string); !ok || uri != "src/main.go" {
		t.Errorf("expected uri 'src/main.go', got %v", artifactLoc["uri"])
	}

	// Check region
	region, ok := physLoc["region"].(map[string]any)
	if !ok {
		t.Fatal("expected region map")
	}

	if line, ok := region["startLine"].(int); !ok || line != 42 {
		t.Errorf("expected startLine 42, got %v", region["startLine"])
	}
}

func TestNewSARIFRule(t *testing.T) {
	t.Parallel()

	rule := format.NewSARIFRule("SEC001", "Security vulnerability detected")

	if rule.Id != "SEC001" {
		t.Errorf("expected id 'SEC001', got %q", rule.Id)
	}

	if rule.ShortDescription == nil {
		t.Fatal("expected short description")
	}

	if rule.ShortDescription.Text != "Security vulnerability detected" {
		t.Errorf("expected description text, got %q", rule.ShortDescription.Text)
	}
}

func TestSARIFReport_AddResults(t *testing.T) {
	t.Parallel()

	report := format.NewSARIFReport()

	// Add some results
	result1 := format.NewSARIFResult("RULE1", format.SARIFLevelError, "Error 1")
	result2 := format.NewSARIFResultWithLocation("RULE2", format.SARIFLevelWarning, "Warning", "file.go", 10)

	report.Runs[0].Results = append(report.Runs[0].Results, result1, result2)

	if len(report.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(report.Runs[0].Results))
	}

	// Verify it marshals correctly
	//nolint:musttag
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal report with results: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty JSON output")
	}
}

func TestSARIFReport_AddRules(t *testing.T) {
	t.Parallel()

	report := format.NewSARIFReport()

	rule1 := format.NewSARIFRule("RULE1", "First rule")
	rule2 := format.NewSARIFRule("RULE2", "Second rule")

	report.Runs[0].Tool.Driver.Rules = append(report.Runs[0].Tool.Driver.Rules, rule1, rule2)

	if len(report.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(report.Runs[0].Tool.Driver.Rules))
	}

	// Verify it marshals correctly
	//nolint:musttag
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("failed to marshal report with rules: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty JSON output")
	}
}
