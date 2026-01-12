package version

import "errors"

var (
	// ErrNoValidVersionsFound indicates no valid versions were found for the image.
	// This means the referenced tag has been deleted and there is no alternative including the tag prefix/suffix.
	// Generally indicative that something bad happened to that image...
	ErrNoValidVersionsFound = errors.New("no valid version found")
	// ErrUnableToListTags indicates failure to list repository tags. Service error.
	ErrUnableToListTags = errors.New("failed to list tags")
	// ErrUnableToGetDigest indicates failure to get version digest. Service error.
	ErrUnableToGetDigest = errors.New("failed to get latest version digest")
)
