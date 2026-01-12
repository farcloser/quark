package layers

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	deckodertypes "github.com/goodwithtech/deckoder/types"
	"github.com/goodwithtech/dockle/pkg/assessor/credential"
	"github.com/goodwithtech/dockle/pkg/assessor/group"
	"github.com/goodwithtech/dockle/pkg/assessor/passwd"
	"github.com/goodwithtech/dockle/pkg/assessor/privilege"
	"github.com/goodwithtech/dockle/pkg/assessor/user"
	dockletypes "github.com/goodwithtech/dockle/pkg/types"
)

// wrapperScanner uses dockle's assessors directly.
type wrapperScanner struct {
	opts Options
}

// newWrapperScanner creates a scanner that wraps dockle's assessors.
func newWrapperScanner(opts Options) *wrapperScanner {
	// Configure dockle's additional patterns if provided.
	if len(opts.AdditionalCredentialFiles) > 0 {
		credential.AddSensitiveFiles(opts.AdditionalCredentialFiles)
	}

	if len(opts.AdditionalCredentialExtensions) > 0 {
		credential.AddSensitiveFileExtensions(opts.AdditionalCredentialExtensions)
	}

	return &wrapperScanner{opts: opts}
}

// Scan scans each layer using dockle's assessors.
func (s *wrapperScanner) Scan(ctx context.Context, layers []io.Reader) (*Result, error) {
	var allAssessments []*Assessment

	for layerIdx, layer := range layers {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %w", ErrAnalysisFailed, ctx.Err())
		default:
		}

		assessments, err := s.analyzeLayer(ctx, layer, layerIdx)
		if err != nil {
			return nil, fmt.Errorf("%w: layer %d: %w", ErrAnalysisFailed, layerIdx, err)
		}

		allAssessments = append(allAssessments, assessments...)
	}

	return &Result{Assessments: allAssessments}, nil
}

// analyzeLayer scans a single layer using dockle's assessors.
func (s *wrapperScanner) analyzeLayer(_ context.Context, layer io.Reader, layerIdx int) ([]*Assessment, error) {
	// Build FileMap from tar.
	fileMap, err := s.buildFileMap(layer)
	if err != nil {
		return nil, err
	}

	var allAssessments []*Assessment

	// Run dockle assessors.
	assessors := []interface {
		Assess(deckodertypes.FileMap) ([]*dockletypes.Assessment, error)
	}{
		credential.CredentialAssessor{},
		passwd.PasswdAssessor{},
		user.UserAssessor{},
		group.GroupAssessor{},
		privilege.PrivilegeAssessor{},
	}

	for _, assessor := range assessors {
		results, assessErr := assessor.Assess(fileMap)
		if assessErr != nil {
			return nil, fmt.Errorf("assessor failed: %w", assessErr)
		}

		for _, result := range results {
			allAssessments = append(allAssessments, convertDockleAssessment(result, layerIdx))
		}
	}

	return allAssessments, nil
}

// buildFileMap reads a tar stream and builds a dockle FileMap.
func (s *wrapperScanner) buildFileMap(layer io.Reader) (deckodertypes.FileMap, error) {
	fileMap := make(deckodertypes.FileMap)
	tarReader := tar.NewReader(layer)

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidTar, err)
		}

		// Skip whiteout files.
		fileName := filepath.Base(header.Name)
		if strings.HasPrefix(fileName, ".wh.") {
			continue
		}

		// Skip directories.
		if header.Typeflag == tar.TypeDir {
			continue
		}

		filePath := filepath.Clean(header.Name)
		fileMode := header.FileInfo().Mode()

		// Read content for regular files.
		var content []byte

		if header.Typeflag == tar.TypeReg {
			content, err = io.ReadAll(tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read %s: %w", filePath, err)
			}
		}

		fileMap[filePath] = deckodertypes.FileData{
			Body:     content,
			FileMode: fileMode,
		}
	}

	return fileMap, nil
}

// convertDockleAssessment converts a dockle assessment to our type.
func convertDockleAssessment(dockleResult *dockletypes.Assessment, layerIdx int) *Assessment {
	level := LevelInfo

	if lvl, ok := DefaultLevels[dockleResult.Code]; ok {
		level = lvl
	}

	title := dockleResult.Code
	if t, ok := Titles[dockleResult.Code]; ok {
		title = t
	}

	return &Assessment{
		Code:       dockleResult.Code,
		Title:      title,
		Level:      level,
		Message:    dockleResult.Desc,
		LayerIndex: layerIdx,
		Filename:   dockleResult.Filename,
	}
}
