package layers

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// Files that need content analysis (not just header inspection).
var filesNeedingContent = map[string]struct{}{
	"etc/shadow":        {},
	"etc/master.passwd": {},
	"etc/passwd":        {},
	"etc/group":         {},
}

// nativeScanner implements layer analysis without external dependencies.
type nativeScanner struct {
	credentialChecker *credentialChecker
	privilegeChecker  *privilegeChecker
	passwordChecker   *passwordChecker
	identityChecker   *identityChecker
	deletableChecker  *deletableChecker
}

// newNativeScanner creates a scanner with native implementation.
func newNativeScanner(opts Options) *nativeScanner {
	return &nativeScanner{
		credentialChecker: newCredentialChecker(opts),
		privilegeChecker:  newPrivilegeChecker(),
		passwordChecker:   newPasswordChecker(),
		identityChecker:   newIdentityChecker(),
		deletableChecker:  newDeletableChecker(),
	}
}

// Scan scans each layer independently for security issues.
func (s *nativeScanner) Scan(ctx context.Context, layers []io.Reader) (*Result, error) {
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

// analyzeLayer scans a single layer tar stream.
func (s *nativeScanner) analyzeLayer(ctx context.Context, layer io.Reader, layerIdx int) ([]*Assessment, error) {
	var assessments []*Assessment

	// Reset per-layer state in checkers.
	s.deletableChecker.reset()

	tarReader := tar.NewReader(layer)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidTar, err)
		}

		// Skip whiteout files (deleted files marker).
		fileName := filepath.Base(header.Name)
		if strings.HasPrefix(fileName, ".wh.") {
			continue
		}

		// Clean the path.
		filePath := filepath.Clean(header.Name)

		// Build file entry.
		entry := FileEntry{
			Path: filePath,
			Mode: header.FileInfo().Mode(),
		}

		// Read content only for files that need it.
		if _, needsContent := filesNeedingContent[filePath]; needsContent && header.Typeflag == tar.TypeReg {
			content, readErr := io.ReadAll(tarReader)
			if readErr != nil {
				return nil, fmt.Errorf("failed to read %s: %w", filePath, readErr)
			}

			entry.Content = content
		}

		// Run all checkers.
		assessments = append(assessments, s.checkEntry(entry, layerIdx)...)
	}

	return assessments, nil
}

// checkEntry runs all checkers on a file entry.
func (s *nativeScanner) checkEntry(entry FileEntry, layerIdx int) []*Assessment {
	var assessments []*Assessment

	// Credential check (filename/extension).
	if assessment := s.credentialChecker.check(entry); assessment != nil {
		assessment.LayerIndex = layerIdx
		assessments = append(assessments, assessment)
	}

	// Privilege check (SUID/SGID).
	if assessment := s.privilegeChecker.check(entry); assessment != nil {
		assessment.LayerIndex = layerIdx
		assessments = append(assessments, assessment)
	}

	// Password check (empty password in /etc/shadow).
	passwordAssessments := s.passwordChecker.check(entry)
	for _, assessment := range passwordAssessments {
		assessment.LayerIndex = layerIdx
		assessments = append(assessments, assessment)
	}

	// Identity check (duplicate UID/GID).
	identityAssessments := s.identityChecker.check(entry)
	for _, assessment := range identityAssessments {
		assessment.LayerIndex = layerIdx
		assessments = append(assessments, assessment)
	}

	// Deletable files check (unnecessary files/directories).
	if assessment := s.deletableChecker.check(entry); assessment != nil {
		assessment.LayerIndex = layerIdx
		assessments = append(assessments, assessment)
	}

	return assessments
}
