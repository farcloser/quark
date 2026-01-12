package config

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	metadataFilename = "metadata"
	equalsSeparator  = "="
)

// nativeScanner implements config analysis without external dependencies.
type nativeScanner struct {
	sensitivePattern *regexp.Regexp
	acceptedKeys     map[string]struct{}
}

// newNativeScanner creates a scanner with native implementation.
func newNativeScanner(opts Options) *nativeScanner {
	// Build sensitive pattern
	suspiciousKeys := []string{"PASS", "PASSWD", "PASSWORD", "SECRET", "KEY", "ACCESS", "TOKEN"}
	suspiciousKeys = append(suspiciousKeys, opts.AdditionalSensitiveWords...)

	pattern := `(?i)(` + strings.Join(suspiciousKeys, "|") + `)`
	//nolint:errcheck // Pattern is constructed from known-valid strings.
	sensitivePattern, _ := regexp.Compile(pattern)

	// Build accepted keys map
	acceptedKeys := map[string]struct{}{
		"GPG_KEY":  {},
		"GPG_KEYS": {},
	}

	for _, key := range opts.AcceptedEnvKeys {
		acceptedKeys[key] = struct{}{}
	}

	return &nativeScanner{
		sensitivePattern: sensitivePattern,
		acceptedKeys:     acceptedKeys,
	}
}

// Scan examines the config and returns findings.
func (s *nativeScanner) Scan(config []byte) (*Result, error) {
	var img ImageConfig
	if err := json.Unmarshal(config, &img); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	var assessments []*Assessment

	// Check history entries
	historyAssessments := s.analyzeHistory(img.History)
	assessments = append(assessments, historyAssessments...)

	// Check user
	if img.Config.User == "" || img.Config.User == "root" {
		assessments = append(assessments, &Assessment{
			Code:     CodeAvoidRootDefault,
			Title:    Titles[CodeAvoidRootDefault],
			Level:    DefaultLevels[CodeAvoidRootDefault],
			Message:  "Last user should not be root",
			Filename: metadataFilename,
		})
	}

	// Check healthcheck
	if img.Config.Healthcheck == nil {
		assessments = append(assessments, &Assessment{
			Code:     CodeAddHealthcheck,
			Title:    Titles[CodeAddHealthcheck],
			Level:    DefaultLevels[CodeAddHealthcheck],
			Message:  "not found HEALTHCHECK statement",
			Filename: metadataFilename,
		})
	}

	// Check volumes for sensitive directories
	sensitiveDirs := map[string]struct{}{"/sys": {}, "/dev": {}, "/proc": {}}
	for volume := range img.Config.Volumes {
		if _, ok := sensitiveDirs[volume]; ok {
			assessments = append(assessments, &Assessment{
				Code:     CodeAvoidSensitiveDirectoryMounting,
				Title:    Titles[CodeAvoidSensitiveDirectoryMounting],
				Level:    DefaultLevels[CodeAvoidSensitiveDirectoryMounting],
				Message:  "Avoid mounting sensitive dirs : " + volume,
				Filename: metadataFilename,
			})
		}
	}

	return &Result{Assessments: assessments}, nil
}

// analyzeHistory examines history entries for issues.
func (s *nativeScanner) analyzeHistory(history []History) []*Assessment {
	var assessments []*Assessment

	// Track first ADD statement to exclude from warnings
	firstAddIndex := -1

	for historyIdx, h := range history {
		cmd := h.CreatedBy
		cmdSlices := splitByCommands(cmd)

		// Check for sensitive environment variables
		if varName, varVal, found := s.findSensitiveVars(cmd); found {
			masked := strings.ReplaceAll(cmd, varVal, "*******")
			assessments = append(assessments, &Assessment{
				Code:     CodeAvoidCredential,
				Title:    Titles[CodeAvoidCredential],
				Level:    DefaultLevels[CodeAvoidCredential],
				Message:  fmt.Sprintf("Suspicious ENV key found : %s on %s", varName, masked),
				Filename: metadataFilename,
			})
		}

		// Check apk add without --no-cache
		if reducableApkAdd(cmdSlices) {
			assessments = append(assessments, &Assessment{
				Code:     CodeUseApkAddNoCache,
				Title:    Titles[CodeUseApkAddNoCache],
				Level:    DefaultLevels[CodeUseApkAddNoCache],
				Message:  "Use --no-cache option if use 'apk add': " + cmd,
				Filename: metadataFilename,
			})
		}

		// Check apt-get install without cleanup
		if reducableAptGetInstall(cmdSlices) {
			assessments = append(assessments, &Assessment{
				Code:     CodeMinimizeAptGet,
				Title:    Titles[CodeMinimizeAptGet],
				Level:    DefaultLevels[CodeMinimizeAptGet],
				Message:  "Use 'rm -rf /var/lib/apt/lists' after 'apt-get install|update' : " + cmd,
				Filename: metadataFilename,
			})
		}

		// Check apt-get update without install
		if reducableAptGetUpdate(cmdSlices) {
			assessments = append(assessments, &Assessment{
				Code:     CodeUseAptGetUpdateNoCache,
				Title:    Titles[CodeUseAptGetUpdateNoCache],
				Level:    DefaultLevels[CodeUseAptGetUpdateNoCache],
				Message:  "Always combine 'apt-get update' with 'apt-get install|upgrade' : " + cmd,
				Filename: metadataFilename,
			})
		}

		// Check ADD statement (except first one)
		if useADDStatement(cmdSlices) {
			if firstAddIndex == -1 {
				firstAddIndex = historyIdx
			} else {
				assessments = append(assessments, &Assessment{
					Code:     CodeUseCOPY,
					Title:    Titles[CodeUseCOPY],
					Level:    DefaultLevels[CodeUseCOPY],
					Message:  "Use COPY : " + cmd,
					Filename: metadataFilename,
				})
			}
		}

		// Check dist-upgrade
		if useDistUpgrade(cmdSlices) {
			assessments = append(assessments, &Assessment{
				Code:     CodeAvoidDistUpgrade,
				Title:    Titles[CodeAvoidDistUpgrade],
				Level:    DefaultLevels[CodeAvoidDistUpgrade],
				Message:  "Avoid dist-upgrade in container : " + cmd,
				Filename: metadataFilename,
			})
		}

		// Check sudo usage
		if useSudo(cmdSlices) {
			assessments = append(assessments, &Assessment{
				Code:     CodeAvoidSudo,
				Title:    Titles[CodeAvoidSudo],
				Level:    DefaultLevels[CodeAvoidSudo],
				Message:  "Avoid sudo in container : " + cmd,
				Filename: metadataFilename,
			})
		}
	}

	return assessments
}

// findSensitiveVars looks for sensitive environment variables in a command.
func (s *nativeScanner) findSensitiveVars(cmd string) (varName, varVal string, found bool) {
	if !strings.Contains(cmd, equalsSeparator) {
		return "", "", false
	}

	// Simple tokenization - split by whitespace and look for key=value
	// Remove comment markers
	cleanCmd := strings.ReplaceAll(cmd, "#", "")
	tokens := strings.FieldsSeq(cleanCmd)

	for token := range tokens {
		if !strings.Contains(token, equalsSeparator) {
			continue
		}

		parts := strings.SplitN(token, equalsSeparator, 2)
		if len(parts) != 2 {
			continue
		}

		key, val := parts[0], parts[1]

		// Skip if value is empty
		if val == "" {
			continue
		}

		// Skip if key contains spaces (invalid)
		if strings.Contains(key, " ") {
			continue
		}

		// Skip accepted keys
		if _, ok := s.acceptedKeys[key]; ok {
			continue
		}

		// Check if key matches sensitive pattern
		if s.sensitivePattern.MatchString(key) {
			return key, val, true
		}
	}

	return "", "", false
}

// splitByCommands splits a command line by && into individual commands.
func splitByCommands(line string) map[int][]string {
	commands := strings.Split(line, "&&")
	tokens := make(map[int][]string)

	for index, command := range commands {
		parts := strings.Fields(command)
		tokens[index] = parts
	}

	return tokens
}

// containsAll checks if haystack contains all needles.
func containsAll(haystack, needles []string) bool {
	needleMap := make(map[string]struct{})
	for _, n := range needles {
		needleMap[n] = struct{}{}
	}

	for _, v := range haystack {
		if _, ok := needleMap[v]; ok {
			delete(needleMap, v)

			if len(needleMap) == 0 {
				return true
			}
		}
	}

	return false
}

// containsThreshold checks if haystack contains at least threshold needles.
func containsThreshold(haystack, needles []string, threshold int) bool {
	needleMap := make(map[string]struct{})
	for _, n := range needles {
		needleMap[n] = struct{}{}
	}

	count := 0

	for _, v := range haystack {
		if _, ok := needleMap[v]; ok {
			delete(needleMap, v)

			count++

			if count >= threshold {
				return true
			}
		}
	}

	return false
}

// reducableApkAdd checks if apk add is used without --no-cache.
func reducableApkAdd(cmdSlices map[int][]string) bool {
	for _, cmdSlice := range cmdSlices {
		if containsAll(cmdSlice, []string{"apk", "add"}) {
			if !containsAll(cmdSlice, []string{"--no-cache"}) {
				return true
			}
		}
	}

	return false
}

// checkAptCommand checks for apt/apt-get with a specific subcommand.
func checkAptCommand(target []string, command string) bool {
	return containsThreshold(target, []string{"apt-get", "apt", command}, 2)
}

// reducableAptGetInstall checks if apt-get install/update is used without cleanup.
func reducableAptGetInstall(cmdSlices map[int][]string) bool {
	var useAptLibrary bool

	removeAptLibCmds := []string{
		"rm", "-rf", "-fr", "-r", "-fR",
		"/var/lib/apt/lists", "/var/lib/apt/lists/*", "/var/lib/apt/lists/*;",
	}

	for cmdIdx := range len(cmdSlices) {
		cmdSlice := cmdSlices[cmdIdx]

		if !useAptLibrary && (checkAptCommand(cmdSlice, "update") || checkAptCommand(cmdSlice, "install")) {
			useAptLibrary = true
		}

		if useAptLibrary && containsThreshold(cmdSlice, removeAptLibCmds, 3) {
			return false
		}
	}

	return useAptLibrary
}

// reducableAptGetUpdate checks if apt-get update is used without install/upgrade.
func reducableAptGetUpdate(cmdSlices map[int][]string) bool {
	var useAptUpdate bool

	for cmdIdx := range len(cmdSlices) {
		cmdSlice := cmdSlices[cmdIdx]

		if !useAptUpdate && checkAptCommand(cmdSlice, "update") {
			useAptUpdate = true
		}

		if useAptUpdate {
			if checkAptCommand(cmdSlice, "install") || checkAptCommand(cmdSlice, "upgrade") {
				return false
			}
		}
	}

	return useAptUpdate
}

// useADDStatement checks if ADD is used (vs COPY).
func useADDStatement(cmdSlices map[int][]string) bool {
	for _, cmdSlice := range cmdSlices {
		if containsAll(cmdSlice, []string{"ADD", "in"}) || containsAll(cmdSlice, []string{"ADD", "buildkit"}) {
			return true
		}
	}

	return false
}

// useDistUpgrade checks if apt-get dist-upgrade is used.
func useDistUpgrade(cmdSlices map[int][]string) bool {
	for _, cmdSlice := range cmdSlices {
		if checkAptCommand(cmdSlice, "dist-upgrade") {
			return true
		}
	}

	return false
}

// useSudo checks if sudo is used.
func useSudo(cmdSlices map[int][]string) bool {
	for _, cmdSlice := range cmdSlices {
		if containsAll(cmdSlice, []string{"sudo"}) {
			return true
		}
	}

	return false
}
