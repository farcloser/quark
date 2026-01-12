package syft

import "errors"

var (
	// ErrTarballOpenFailed indicates the OCI tarball could not be opened.
	ErrTarballOpenFailed = errors.New("failed to open OCI tarball")
	// ErrTarballExtractFailed indicates the OCI tarball could not be extracted.
	ErrTarballExtractFailed = errors.New("failed to extract OCI tarball")
	// ErrInvalidOCILayout indicates the tarball does not contain a valid OCI layout.
	ErrInvalidOCILayout = errors.New("invalid OCI layout")
	// ErrPlatformNotFound indicates the requested platform was not found in the image.
	ErrPlatformNotFound = errors.New("platform not found in image")
	// ErrSourceCreationFailed indicates the image source could not be created.
	ErrSourceCreationFailed = errors.New("failed to create image source")
	// ErrSBOMCreationFailed indicates SBOM generation failed.
	ErrSBOMCreationFailed = errors.New("failed to create SBOM")
	// ErrSBOMEncodingFailed indicates SBOM encoding to CycloneDX failed.
	ErrSBOMEncodingFailed = errors.New("failed to encode SBOM")
	// ErrSBOMDecodingFailed indicates SBOM decoding from CycloneDX failed.
	ErrSBOMDecodingFailed = errors.New("failed to decode SBOM")
	// ErrCancelled indicates the operation was cancelled.
	ErrCancelled = errors.New("SBOM generation cancelled")
	// ErrInvalidPlatform indicates an invalid platform specifier.
	ErrInvalidPlatform = errors.New("invalid platform")
)
