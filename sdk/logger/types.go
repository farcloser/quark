package logger

import (
	"github.com/farcloser/quark/dev/format"
	"github.com/farcloser/quark/sdk/audit"
	"github.com/farcloser/quark/sdk/lint"
	"github.com/farcloser/quark/sdk/scan"
)

// Action is an alias for format.Severity for user convenience.
// It represents what log level to use when outputting results.
type Action = format.Severity

// Action constants aliased from shared package.
//
//nolint:gochecknoglobals // Action enum pattern requires global variables
var (
	// ActionError logs at error level.
	ActionError = format.Error
	// ActionWarn logs at warning level.
	ActionWarn = format.Warn
	// ActionInfo logs at info level.
	ActionInfo = format.Info
	// ActionDebug logs at debug level.
	ActionDebug = format.Debug
)

// Format is an alias for format.Display for user convenience.
type Format = format.Display

// Format constants aliased from shared package.
//
//nolint:gochecknoglobals // Format enum pattern requires global variables
var (
	// FormatTable outputs results as a formatted table.
	FormatTable = format.DisplayTable
	// FormatJSON outputs results as JSON.
	FormatJSON = format.DisplayJSON
	// FormatSARIF outputs results in SARIF format.
	FormatSARIF = format.DisplaySARIF
)

// Options configures log behavior.
type Options struct {
	// Format specifies the output format (default: table).
	Format *Format

	// ScanLevels maps vulnerability severities to log actions.
	// If nil, all vulnerabilities are logged at info level.
	ScanLevels []ScanLevel

	// AuditLevels maps audit issue levels to log actions.
	// If nil, all audit issues are logged at info level.
	AuditLevels []AuditLevel

	// LintLevels maps lint issue severities to log actions.
	// If nil, all lint issues are logged at info level.
	LintLevels []LintLevel
}

// ScanLevel maps vulnerability severities to a log action.
type ScanLevel struct {
	// Severities to match.
	Severities []*scan.Severity `json:"severities,omitempty"`

	// Action determines the log level for matching vulnerabilities.
	Action *Action `json:"action,omitempty"`
}

// AuditLevel maps audit issue levels to a log action.
type AuditLevel struct {
	// Severities to match.
	Severities []*audit.Severity `json:"severities,omitempty"`

	// Action determines the log level for matching issues.
	Action *Action `json:"action,omitempty"`
}

// LintLevel maps lint issue severities to a log action.
type LintLevel struct {
	// Severities to match.
	Severities []*lint.Severity `json:"severities,omitempty"`

	// Action determines the log level for matching issues.
	Action *Action `json:"action,omitempty"`
}

// Preset logging configurations.
//
//nolint:gochecknoglobals // Preset sets require global variables
var (
	// ScanLevelsDefault logs CRITICAL/HIGH at error, MEDIUM at warn, LOW/UNKNOWN at info.
	ScanLevelsDefault = []ScanLevel{
		{Severities: []*scan.Severity{scan.SeverityCritical, scan.SeverityHigh}, Action: ActionError},
		{Severities: []*scan.Severity{scan.SeverityMedium}, Action: ActionWarn},
		{Severities: []*scan.Severity{scan.SeverityLow, scan.SeverityUnknown}, Action: ActionInfo},
	}

	// ScanLevelsQuiet only logs CRITICAL/HIGH at error level.
	ScanLevelsQuiet = []ScanLevel{
		{Severities: []*scan.Severity{scan.SeverityCritical, scan.SeverityHigh}, Action: ActionError},
	}

	// AuditLevelsDefault logs FATAL at error, WARN at warn, INFO at info.
	AuditLevelsDefault = []AuditLevel{
		{Severities: []*audit.Severity{audit.SeverityFatal}, Action: ActionError},
		{Severities: []*audit.Severity{audit.SeverityWarn}, Action: ActionWarn},
		{Severities: []*audit.Severity{audit.SeverityInfo}, Action: ActionInfo},
	}

	// AuditLevelsQuiet only logs FATAL at error level.
	AuditLevelsQuiet = []AuditLevel{
		{Severities: []*audit.Severity{audit.SeverityFatal}, Action: ActionError},
	}

	// LintLevelsDefault logs error at error, warning at warn, info/style at info.
	LintLevelsDefault = []LintLevel{
		{Severities: []*lint.Severity{lint.SeverityError}, Action: ActionError},
		{Severities: []*lint.Severity{lint.SeverityWarning}, Action: ActionWarn},
		{Severities: []*lint.Severity{lint.SeverityInfo, lint.SeverityStyle}, Action: ActionInfo},
	}

	// LintLevelsStrict logs error and warning at error level.
	LintLevelsStrict = []LintLevel{
		{Severities: []*lint.Severity{lint.SeverityError, lint.SeverityWarning}, Action: ActionError},
		{Severities: []*lint.Severity{lint.SeverityInfo}, Action: ActionWarn},
	}

	// LintLevelsQuiet only logs error at error level.
	LintLevelsQuiet = []LintLevel{
		{Severities: []*lint.Severity{lint.SeverityError}, Action: ActionError},
	}
)
