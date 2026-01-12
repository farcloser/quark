package policy

import "errors"

// Sentinel errors for policy operations.
var (
	// ErrCheckFailed is returned when a policy check fails.
	ErrCheckFailed = errors.New("policy check failed")

	// ErrInvalidInput is returned when the policy receives an unexpected input type.
	ErrInvalidInput = errors.New("invalid policy input")

	// ErrExpectedImageInput is returned when a policy expected ImageInput but received something else.
	ErrExpectedImageInput = errors.New("expected ImageInput")

	// ErrExpectedBuilderInput is returned when a policy expected BuilderInput but received something else.
	ErrExpectedBuilderInput = errors.New("expected BuilderInput")

	// ErrImageNotSigned is returned when a signature policy receives an unsigned image.
	ErrImageNotSigned = errors.New("image is not signed")
)
