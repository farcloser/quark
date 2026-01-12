package layers

import (
	"bufio"
	"bytes"
	"strings"
)

// Password files to check for empty passwords.
//
//nolint:gochecknoglobals // Read-only configuration.
var passwordFiles = map[string]struct{}{
	"etc/shadow":        {},
	"etc/master.passwd": {},
}

type passwordChecker struct{}

func newPasswordChecker() *passwordChecker {
	return &passwordChecker{}
}

func (c *passwordChecker) check(entry FileEntry) []*Assessment {
	// Only check password files.
	if _, isPasswordFile := passwordFiles[entry.Path]; !isPasswordFile {
		return nil
	}

	// Need content to analyze.
	if entry.Content == nil {
		return nil
	}

	var assessments []*Assessment

	scanner := bufio.NewScanner(bytes.NewReader(entry.Content))
	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines and comments.
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Format: username:password:...
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}

		username := fields[0]
		passwordField := fields[1]

		// Empty password field means no password set.
		if passwordField == "" {
			assessments = append(assessments, &Assessment{
				Code:     CodeAvoidEmptyPassword,
				Title:    Titles[CodeAvoidEmptyPassword],
				Level:    DefaultLevels[CodeAvoidEmptyPassword],
				Message:  "No password user found: " + username,
				Filename: entry.Path,
			})
		}
	}

	return assessments
}
