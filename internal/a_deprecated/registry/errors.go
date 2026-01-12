package registry

import "errors"

var (
	// ErrParseSourceReference indicates failure parsing a source reference.
	ErrParseSourceReference = errors.New("failed to parse source reference")
	// ErrParseManifestReference indicates failure parsing a manifest reference.
	ErrParseManifestReference = errors.New("failed to parse manifest reference")
	// ErrGetImage indicates failure retrieving an image from the registry.
	ErrGetImage = errors.New("failed to get image")
	// ErrGetImageIndex indicates failure retrieving an image index from the registry.
	ErrGetImageIndex = errors.New("failed to get image index")
	// ErrGetSourceImage indicates failure retrieving source image.
	ErrGetSourceImage = errors.New("failed to get source image")
	// ErrWriteDestinationImage indicates failure writing image to destination.
	ErrWriteDestinationImage = errors.New("failed to write destination image")
	// ErrGetSourceIndex indicates failure retrieving source image index.
	ErrGetSourceIndex = errors.New("failed to get source index")
	// ErrWriteDestinationIndex indicates failure writing image index to destination.
	ErrWriteDestinationIndex = errors.New("failed to write destination index")
	// ErrGetIndexManifest indicates failure getting index manifest.
	ErrGetIndexManifest = errors.New("failed to get index manifest")
	// ErrPushManifestList indicates failure pushing manifest list.
	ErrPushManifestList = errors.New("failed to push manifest list")
	// ErrGetManifestListDigest indicates failure getting manifest list digest.
	ErrGetManifestListDigest = errors.New("failed to get manifest list digest")
	// ErrCheckImageExistence indicates failure checking image existence.
	ErrCheckImageExistence = errors.New("failed to check image existence")
	// ErrParseRepository indicates failure parsing repository.
	ErrParseRepository = errors.New("failed to parse repository")
	// ErrListTags indicates failure listing repository tags.
	ErrListTags = errors.New("failed to list tags")
	// ErrWriteImage indicates failure writing an image to the registry.
	ErrWriteImage = errors.New("failed to write image")
	// ErrComputeDigest indicates failure computing image digest.
	ErrComputeDigest = errors.New("failed to compute digest")
	// ErrFetchPlatformImage indicates failure fetching a platform-specific image.
	ErrFetchPlatformImage = errors.New("failed to fetch platform image")
)
