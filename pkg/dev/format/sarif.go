package format

import (
	"github.com/farcloser/quark/pkg/dev/format/sarif"
	"github.com/farcloser/quark/pkg/version"
)

const (
	// SARIFSchema is the JSON schema URI for SARIF 2.1.0.
	SARIFSchema = "https://json.schemastore.org/sarif-2.1.0.json"
	// SARIFLevelError is the SARIF level for errors.
	SARIFLevelError = sarif.ResultLevelError
	// SARIFLevelWarning is the SARIF level for warnings.
	SARIFLevelWarning = sarif.ResultLevelWarning
	// SARIFLevelNote is the SARIF level for notes/info.
	SARIFLevelNote = sarif.ResultLevelNote
	// QuarkInfoURI is the information URI for the Quark tool.
	QuarkInfoURI = "https://github.com/farcloser/quark"
)

// NewSARIFReport creates a new SARIF 2.1.0 report with a single run.
// The run is configured with Quark as the tool driver.
func NewSARIFReport() *sarif.SarifSchema210Json {
	schema := SARIFSchema
	infoURI := QuarkInfoURI
	ver := version.Version()

	return &sarif.SarifSchema210Json{
		Schema:  &schema,
		Version: sarif.SarifSchema210JsonVersionA210,
		Runs: []sarif.Run{
			{
				Tool: sarif.Tool{
					Driver: sarif.ToolComponent{
						Name:           version.Name(),
						Version:        &ver,
						InformationUri: &infoURI,
					},
				},
				Results: []sarif.Result{},
			},
		},
	}
}

// NewSARIFResult creates a new SARIF result with the given rule ID, level, and message.
func NewSARIFResult(ruleID string, level sarif.ResultLevel, message string) sarif.Result {
	return sarif.Result{
		RuleId:  &ruleID,
		Level:   level,
		Message: message,
	}
}

// NewSARIFResultWithLocation creates a new SARIF result with a physical location.
// Use this for findings that have a specific file and line number (e.g., Dockerfile lint).
func NewSARIFResultWithLocation(
	ruleID string,
	level sarif.ResultLevel,
	message string,
	uri string,
	line int,
) sarif.Result {
	result := NewSARIFResult(ruleID, level, message)
	result.Locations = []sarif.Location{
		{
			PhysicalLocation: map[string]any{
				"artifactLocation": map[string]any{
					"uri": uri,
				},
				"region": map[string]any{
					"startLine": line,
				},
			},
		},
	}

	return result
}

// NewSARIFRule creates a new reporting descriptor (rule) for the SARIF report.
func NewSARIFRule(id, shortDescription string) sarif.ReportingDescriptor {
	return sarif.ReportingDescriptor{
		Id: id,
		ShortDescription: &sarif.MultiformatMessageString{
			Text: shortDescription,
		},
	}
}
