// Package logger provides result logging for quark operations.
//
// The Log action outputs scan/audit results to the logger with configurable
// format and severity-to-log-level mapping.
//
// Example usage:
//
//	// Log scan results with severity filtering
//	scanned := img.Scan(scanOpts)
//	logged := scanned.Log(&log.Options{
//	    Format: log.FormatTable,
//	    ScanLevels: []log.ScanLevel{
//	        {Severities: []string{"CRITICAL", "HIGH"}, Action: log.ActionError},
//	        {Severities: []string{"MEDIUM"}, Action: log.ActionWarn},
//	    },
//	})
//
//	// Log audit results
//	audited := img.Audit(auditOpts)
//	logged := audited.Log(&log.Options{
//	    Format: log.FormatSARIF,
//	    AuditLevels: []log.AuditLevel{
//	        {Levels: []string{"FATAL"}, Action: log.ActionError},
//	        {Levels: []string{"WARN"}, Action: log.ActionWarn},
//	    },
//	})
package logger
