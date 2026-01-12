package config

import (
	"fmt"
	"os"

	deckodertypes "github.com/goodwithtech/deckoder/types"
	"github.com/goodwithtech/dockle/pkg/assessor/manifest"
	dockletypes "github.com/goodwithtech/dockle/pkg/types"
)

const defaultFileMode = os.FileMode(0o644)

// wrapperScanner uses dockle's manifest assessor directly.
type wrapperScanner struct {
	opts Options
}

// newWrapperScanner creates a scanner that wraps dockle's manifest assessor.
func newWrapperScanner(opts Options) *wrapperScanner {
	return &wrapperScanner{opts: opts}
}

// Scan examines the config using dockle's manifest assessor.
func (s *wrapperScanner) Scan(config []byte) (*Result, error) {
	// Configure dockle's sensitive words if provided
	if len(s.opts.AdditionalSensitiveWords) > 0 {
		manifest.AddSensitiveWords(s.opts.AdditionalSensitiveWords)
	}

	if len(s.opts.AcceptedEnvKeys) > 0 {
		manifest.AddAcceptanceKeys(s.opts.AcceptedEnvKeys)
	}

	// Create FileMap with config at "/config" path
	fileMap := deckodertypes.FileMap{
		"/config": deckodertypes.FileData{
			Body:     config,
			FileMode: defaultFileMode,
		},
	}

	// Run dockle's manifest assessor
	assessor := manifest.ManifestAssessor{}

	results, err := assessor.Assess(fileMap)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAnalysisFailed, err)
	}

	// Convert dockle results to our types
	assessments := make([]*Assessment, 0, len(results))

	for _, result := range results {
		assessments = append(assessments, convertDockleAssessment(result))
	}

	return &Result{Assessments: assessments}, nil
}

// convertDockleAssessment converts a dockle assessment to our type.
func convertDockleAssessment(dockleAssessment *dockletypes.Assessment) *Assessment {
	level := LevelInfo

	if lvl, ok := DefaultLevels[dockleAssessment.Code]; ok {
		level = lvl
	}

	title := dockleAssessment.Code
	if t, ok := Titles[dockleAssessment.Code]; ok {
		title = t
	}

	return &Assessment{
		Code:     dockleAssessment.Code,
		Title:    title,
		Level:    level,
		Message:  dockleAssessment.Desc,
		Filename: dockleAssessment.Filename,
	}
}
