package sdk

import (
	"context"
	"fmt"
	"log/slog"

	devpolicy "github.com/farcloser/quark/dev/policy"
	"github.com/farcloser/quark/dev/resource"
	"github.com/farcloser/quark/internal/a_deprecated/dockle"
	"github.com/farcloser/quark/sdk/policy"
	"github.com/farcloser/quark/sdk/scan"
)

const (
	logKeyPolicy  = "policy"
	logKeyMessage = "message"
)

type checkAction struct {
	*resource.BaseAction

	policy policy.Policy
	output *Image
}

func (ca *checkAction) AddOutput(name string, out resource.Resource, copyFrom ...resource.Resource) resource.Resource {
	return resource.RegisterOutput(ca, ca.BaseAction, name, out, copyFrom...)
}

func (ca *checkAction) Execute(ctx context.Context) error {
	// Build policy input from the output image state
	// (which has been populated via Bootstrap from the input)
	policyInput := ca.buildPolicyInput()

	result := ca.policy.Evaluate(ctx, policyInput)

	switch result.Verdict {
	case devpolicy.Allow:
		ca.output.log.InfoContext(ctx, "policy check passed",
			slog.String(logKeyPolicy, result.Policy),
			slog.String(logKeyMessage, result.Message),
		)

		return nil

	case devpolicy.Warn:
		ca.output.log.WarnContext(ctx, "policy check warning",
			slog.String(logKeyPolicy, result.Policy),
			slog.String(logKeyMessage, result.Message),
		)

		return nil

	case devpolicy.Skip:
		ca.output.log.DebugContext(ctx, "policy check skipped",
			slog.String(logKeyPolicy, result.Policy),
			slog.String(logKeyMessage, result.Message),
		)

		return nil

	case devpolicy.Deny:
		ca.output.log.ErrorContext(ctx, "policy check failed",
			slog.String(logKeyPolicy, result.Policy),
			slog.String(logKeyMessage, result.Message),
		)

		return fmt.Errorf("%w: %s - %s", policy.ErrCheckFailed, result.Policy, result.Message)

	default:
		return fmt.Errorf("%w: unknown verdict %q from policy %s",
			policy.ErrCheckFailed, result.Verdict, result.Policy)
	}
}

// buildPolicyInput constructs the policy input from the current image state.
func (ca *checkAction) buildPolicyInput() *policy.ImageInput {
	img := ca.output

	policyInput := &policy.ImageInput{
		Reference: img.ref.String(),
		Digest:    img.ref.Digest.String(),
		Domain:    img.registry.options.Domain,
		Name:      img.ref.Path,
		Tag:       img.ref.Tag,
	}

	// Populate scan results if available
	if img.scanResult != nil {
		policyInput.Scan = buildScanInput(img.scanResult)
	}

	// Populate audit results if available
	if img.auditResult != nil {
		policyInput.Audit = buildAuditInput(img.auditResult)
	}

	// Populate signature info if available
	if img.signatureInfo != nil {
		policyInput.Signature = &policy.SignatureInput{
			Signed:     img.signatureInfo.IsSigned,
			IsKeyBased: img.signatureInfo.IsKeyBased,
		}

		if img.signatureInfo.Keyless != nil {
			policyInput.Signature.Issuer = img.signatureInfo.Keyless.Issuer
			policyInput.Signature.Subject = img.signatureInfo.Keyless.Subject
		}
	}

	return policyInput
}

// buildScanInput constructs ScanInput from deduplicated scan results.
func buildScanInput(result *scan.Result) *policy.ScanInput {
	scanInput := &policy.ScanInput{}

	for _, vuln := range result.Vulnerabilities {
		switch vuln.Severity {
		case scan.SeverityCritical:
			scanInput.Critical++
		case scan.SeverityHigh:
			scanInput.High++
		case scan.SeverityMedium:
			scanInput.Medium++
		case scan.SeverityLow:
			scanInput.Low++
		default:
			scanInput.Unknown++
		}
	}

	return scanInput
}

// buildAuditInput constructs AuditInput from dockle audit results.
func buildAuditInput(result *dockle.ScanResult) *policy.AuditInput {
	auditInput := &policy.AuditInput{}

	for _, detail := range result.Details {
		switch detail.Level {
		case "FATAL":
			auditInput.Fatal++
		case "WARN":
			auditInput.Warn++
		case "INFO":
			auditInput.Info++
		default:
			// Ignore unknown levels
		}
	}

	return auditInput
}
