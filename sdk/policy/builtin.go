package policy

import (
	"context"
	"fmt"
	"regexp"

	devpolicy "github.com/farcloser/quark/dev/policy"
)

const (
	Ignore        = -1
	ZeroTolerance = 0
)

// RequireSignature denies unsigned images.
func RequireSignature() Policy {
	return &requireSignature{}
}

type requireSignature struct{}

func (*requireSignature) Name() string { return "require-signature" }

func (pol *requireSignature) Evaluate(_ context.Context, input any) Result {
	img, ok := input.(*ImageInput)
	if !ok {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("%v: got %T", ErrExpectedImageInput, input),
		}
	}

	if img.Signature == nil || !img.Signature.Signed {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: ErrImageNotSigned.Error(),
		}
	}

	return Result{
		Verdict: Allow,
		Policy:  pol.Name(),
		Message: "image is signed",
	}
}

// RequireSignatureFrom requires signature from a specific issuer and subject pattern.
// The subject is matched as a regex pattern.
func RequireSignatureFrom(issuer, subjectPattern string) Policy {
	return &requireSignatureFrom{issuer: issuer, subjectPattern: subjectPattern}
}

type requireSignatureFrom struct {
	issuer         string
	subjectPattern string
}

func (*requireSignatureFrom) Name() string { return "require-signature-from" }

func (pol *requireSignatureFrom) Evaluate(_ context.Context, input any) Result {
	img, ok := input.(*ImageInput)
	if !ok {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("%v: got %T", ErrExpectedImageInput, input),
		}
	}

	if img.Signature == nil || !img.Signature.Signed {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: ErrImageNotSigned.Error(),
		}
	}

	// This policy only works with keyless signatures (which have issuer/subject)
	if img.Signature.IsKeyBased {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: "signature is key-based, not keyless (no issuer/subject available)",
		}
	}

	if pol.issuer != "" && img.Signature.Issuer != pol.issuer {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("issuer mismatch: got %q, want %q", img.Signature.Issuer, pol.issuer),
		}
	}

	if pol.subjectPattern != "" {
		matched, err := regexp.MatchString(pol.subjectPattern, img.Signature.Subject)
		if err != nil {
			return Result{
				Verdict: Deny,
				Policy:  pol.Name(),
				Message: fmt.Sprintf("invalid subject pattern %q: %v", pol.subjectPattern, err),
			}
		}

		if !matched {
			return Result{
				Verdict: Deny,
				Policy:  pol.Name(),
				Message: fmt.Sprintf("subject %q does not match pattern %q", img.Signature.Subject, pol.subjectPattern),
			}
		}
	}

	return Result{
		Verdict: Allow,
		Policy:  pol.Name(),
		Message: fmt.Sprintf("signed by %s (%s)", img.Signature.Subject, img.Signature.Issuer),
	}
}

// RequireKeyBasedSignature requires a key-based (non-keyless) signature.
// This is useful when images are signed with a private key rather than
// using keyless signing via Fulcio/OIDC.
// Note: This only checks that a key-based signature exists, not that it
// was signed with a specific key. For key verification, use a custom policy.
func RequireKeyBasedSignature() Policy {
	return &requireKeyBasedSignature{}
}

type requireKeyBasedSignature struct{}

func (*requireKeyBasedSignature) Name() string { return "require-key-based-signature" }

func (pol *requireKeyBasedSignature) Evaluate(_ context.Context, input any) Result {
	img, ok := input.(*ImageInput)
	if !ok {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("%v: got %T", ErrExpectedImageInput, input),
		}
	}

	if img.Signature == nil || !img.Signature.Signed {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: ErrImageNotSigned.Error(),
		}
	}

	if !img.Signature.IsKeyBased {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: "signature is keyless, not key-based",
		}
	}

	return Result{
		Verdict: Allow,
		Policy:  pol.Name(),
		Message: "image has key-based signature",
	}
}

// Scan policies

// Scan is a policy that checks vulnerability scan results against configured limits.
// Zero = enforce zero vulnerabilities at that level.
// -1 = ignore that level (no enforcement).
// Positive number = maximum allowed vulnerabilities at that level.
// Returns Skip if no scan results are available.
// Returns Deny if any configured limit is exceeded.
type Scan struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

func (Scan) Name() string { return "scan" }

func (pol Scan) Evaluate(_ context.Context, input any) Result {
	img, ok := input.(*ImageInput)
	if !ok {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("%v: got %T", ErrExpectedImageInput, input),
		}
	}

	if img.Scan == nil {
		return Result{
			Verdict: Skip,
			Policy:  pol.Name(),
			Message: "no scan results available",
		}
	}

	// Check critical vulnerabilities (-1 = ignore)
	if pol.Critical != Ignore && img.Scan.Critical > pol.Critical {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("too many critical vulnerabilities: %d (max: %d)", img.Scan.Critical, pol.Critical),
			Meta:    map[string]any{"critical": img.Scan.Critical},
		}
	}

	// Check high vulnerabilities (-1 = ignore)
	if pol.High != Ignore && img.Scan.High > pol.High {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("too many high vulnerabilities: %d (max: %d)", img.Scan.High, pol.High),
			Meta:    map[string]any{"high": img.Scan.High},
		}
	}

	// Check medium vulnerabilities (-1 = ignore)
	if pol.Medium != Ignore && img.Scan.Medium > pol.Medium {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("too many medium vulnerabilities: %d (max: %d)", img.Scan.Medium, pol.Medium),
			Meta:    map[string]any{"medium": img.Scan.Medium},
		}
	}

	// Check low vulnerabilities (-1 = ignore)
	if pol.Low != Ignore && img.Scan.Low > pol.Low {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("too many low vulnerabilities: %d (max: %d)", img.Scan.Low, pol.Low),
			Meta:    map[string]any{"low": img.Scan.Low},
		}
	}

	// Check unknown vulnerabilities (-1 = ignore)
	if pol.Unknown != Ignore && img.Scan.Unknown > pol.Unknown {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("too many unknown vulnerabilities: %d (max: %d)", img.Scan.Unknown, pol.Unknown),
			Meta:    map[string]any{"unknown": img.Scan.Unknown},
		}
	}

	return Result{
		Verdict: Allow,
		Policy:  pol.Name(),
		Message: "vulnerabilities within limits",
	}
}

func ScanStrict() *Scan {
	return &Scan{
		Critical: ZeroTolerance,
		High:     ZeroTolerance,
		Medium:   ZeroTolerance,
		Low:      ZeroTolerance,
		Unknown:  ZeroTolerance,
	}
}

func ScanDefault() *Scan {
	return &Scan{
		Critical: ZeroTolerance,
		High:     ZeroTolerance,
		Medium:   Ignore,
		Low:      Ignore,
		Unknown:  Ignore,
	}
}

// Audit policies

// Audit is a policy that checks audit results against configured limits.
// Zero = enforce zero violations at that level.
// -1 = ignore that level (no enforcement).
// Positive number = maximum allowed violations at that level.
// Returns Skip if no audit results are available.
// Returns Deny if any configured limit is exceeded.
type Audit struct {
	Fatal int
	Warn  int
	Info  int
}

func (Audit) Name() string { return "audit" }

func (pol Audit) Evaluate(_ context.Context, input any) Result {
	img, ok := input.(*ImageInput)
	if !ok {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("%v: got %T", ErrExpectedImageInput, input),
		}
	}

	if img.Audit == nil {
		return Result{
			Verdict: Skip,
			Policy:  pol.Name(),
			Message: "no audit results available",
		}
	}

	// Check fatal violations (-1 = ignore)
	if pol.Fatal != Ignore && img.Audit.Fatal > pol.Fatal {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("too many fatal audit issues: %d (max: %d)", img.Audit.Fatal, pol.Fatal),
			Meta:    map[string]any{"fatal": img.Audit.Fatal},
		}
	}

	// Check warn violations (-1 = ignore)
	if pol.Warn != Ignore && img.Audit.Warn > pol.Warn {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("too many warning audit issues: %d (max: %d)", img.Audit.Warn, pol.Warn),
			Meta:    map[string]any{"warn": img.Audit.Warn},
		}
	}

	// Check info violations (-1 = ignore)
	if pol.Info != Ignore && img.Audit.Info > pol.Info {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("too many info audit issues: %d (max: %d)", img.Audit.Info, pol.Info),
			Meta:    map[string]any{"info": img.Audit.Info},
		}
	}

	return Result{
		Verdict: Allow,
		Policy:  pol.Name(),
		Message: "audit issues within limits",
	}
}

func AuditStrict() *Audit {
	return &Audit{
		Fatal: ZeroTolerance,
		Warn:  ZeroTolerance,
		Info:  ZeroTolerance,
	}
}

func AuditDefault() *Audit {
	return &Audit{
		Fatal: ZeroTolerance,
		Warn:  Ignore,
		Info:  Ignore,
	}
}

// Func wraps a function as a Policy for custom inline policies.
func Func(name string, evalFn func(context.Context, *ImageInput) Result) Policy {
	return &funcPolicy{name: name, fn: evalFn}
}

type funcPolicy struct {
	name string
	fn   func(context.Context, *ImageInput) Result
}

func (pol *funcPolicy) Name() string { return pol.name }

func (pol *funcPolicy) Evaluate(ctx context.Context, input any) Result {
	img, ok := input.(*ImageInput)
	if !ok {
		return Result{
			Verdict: devpolicy.Deny,
			Policy:  pol.name,
			Message: fmt.Sprintf("%v: got %T", ErrExpectedImageInput, input),
		}
	}

	return pol.fn(ctx, img)
}

// Builder policies

// Lint is a policy that checks Dockerfile lint results against configured limits.
// Zero = enforce zero issues at that level.
// -1 = ignore that level (no enforcement).
// Positive number = maximum allowed issues at that level.
// Returns Skip if no lint results are available.
// Returns Deny if any configured limit is exceeded.
type Lint struct {
	Error   int
	Warning int
	Info    int
	Style   int
}

func (Lint) Name() string { return "lint" }

func (pol Lint) Evaluate(_ context.Context, input any) Result {
	builder, ok := input.(*BuilderInput)
	if !ok {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("%v: got %T", ErrExpectedBuilderInput, input),
		}
	}

	if builder.Lint == nil {
		return Result{
			Verdict: Skip,
			Policy:  pol.Name(),
			Message: "no lint results available",
		}
	}

	// Check error issues (-1 = ignore)
	if pol.Error != Ignore && builder.Lint.Error > pol.Error {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("too many lint errors: %d (max: %d)", builder.Lint.Error, pol.Error),
			Meta:    map[string]any{"errors": builder.Lint.Error},
		}
	}

	// Check warning issues (-1 = ignore)
	if pol.Warning != Ignore && builder.Lint.Warning > pol.Warning {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("too many lint warnings: %d (max: %d)", builder.Lint.Warning, pol.Warning),
			Meta:    map[string]any{"warnings": builder.Lint.Warning},
		}
	}

	// Check info issues (-1 = ignore)
	if pol.Info != Ignore && builder.Lint.Info > pol.Info {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("too many lint info issues: %d (max: %d)", builder.Lint.Info, pol.Info),
			Meta:    map[string]any{"info": builder.Lint.Info},
		}
	}

	// Check style issues (-1 = ignore)
	if pol.Style != Ignore && builder.Lint.Style > pol.Style {
		return Result{
			Verdict: Deny,
			Policy:  pol.Name(),
			Message: fmt.Sprintf("too many lint style issues: %d (max: %d)", builder.Lint.Style, pol.Style),
			Meta:    map[string]any{"style": builder.Lint.Style},
		}
	}

	return Result{
		Verdict: Allow,
		Policy:  pol.Name(),
		Message: "lint issues within limits",
	}
}

func LintStrict() *Lint {
	return &Lint{
		Error:   ZeroTolerance,
		Warning: ZeroTolerance,
		Info:    ZeroTolerance,
		Style:   ZeroTolerance,
	}
}

func LintDefault() *Lint {
	return &Lint{
		Error:   ZeroTolerance,
		Warning: ZeroTolerance,
		Info:    ZeroTolerance,
		Style:   Ignore,
	}
}

// BuilderFunc wraps a function as a Policy for custom inline builder policies.
func BuilderFunc(name string, evalFn func(context.Context, *BuilderInput) Result) Policy {
	return &builderFuncPolicy{name: name, fn: evalFn}
}

type builderFuncPolicy struct {
	name string
	fn   func(context.Context, *BuilderInput) Result
}

func (pol *builderFuncPolicy) Name() string { return pol.name }

func (pol *builderFuncPolicy) Evaluate(ctx context.Context, input any) Result {
	builder, ok := input.(*BuilderInput)
	if !ok {
		return Result{
			Verdict: devpolicy.Deny,
			Policy:  pol.name,
			Message: fmt.Sprintf("%v: got %T", ErrExpectedBuilderInput, input),
		}
	}

	return pol.fn(ctx, builder)
}
