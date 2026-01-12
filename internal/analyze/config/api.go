package config

// Assessment represents a single finding from config analysis.
type Assessment struct {
	Code     string // Checkpoint code (e.g., "CIS-DI-0001").
	Title    string // Human-readable title.
	Level    Level  // Severity level.
	Message  string // Detailed description.
	Filename string // Source of the finding (typically "metadata").
}

// Level represents the severity of a finding.
type Level int

// Level constants for assessment severity.
const (
	LevelPass Level = iota + 1
	LevelIgnore
	LevelSkip
	LevelInfo
	LevelWarn
	LevelFatal
)

// String returns the string representation of the level.
func (l Level) String() string {
	switch l {
	case LevelPass:
		return "PASS"
	case LevelIgnore:
		return "IGNORE"
	case LevelSkip:
		return "SKIP"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Result aggregates config scan results.
type Result struct {
	Assessments []*Assessment
}

// Scanner interface for OCI image config analysis.
type Scanner interface {
	Scan(config []byte) (*Result, error)
}

// NewScanner creates a new config scanner using the native implementation.
func NewScanner(opts Options) Scanner {
	return newNativeScanner(opts)
}
