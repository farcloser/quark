package reference

import (
	"errors"
	"path"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
)

// Protocol represents the protocol used for the image reference.
type Protocol string

const shortIDLength = 5

// ImageReference represents a reference to an image, which may include a protocol, domain, path, tag, and digest.
type ImageReference struct {
	Protocol    Protocol
	Digest      digest.Digest
	Tag         string
	ExplicitTag string
	Path        string
	Domain      string

	nn reference.Reference
}

// Name returns the name of the image reference, including the domain and path.
func (ir *ImageReference) Name() string {
	ret := ir.Domain
	if ret != "" {
		ret += "/"
	}

	ret += ir.Path

	return ret
}

// FamiliarName returns a familiar (eg: shortened) name for the image reference.
func (ir *ImageReference) FamiliarName() string {
	if ir.Protocol != "" && ir.Domain == "" {
		return ir.Path
	}

	if ir.nn != nil {
		if v, ok := ir.nn.(reference.Named); ok {
			return reference.FamiliarName(v)
		}
	}

	return ""
}

// FamiliarMatch checks if the image reference matches a familiar pattern.
func (ir *ImageReference) FamiliarMatch(pattern string) (bool, error) {
	if ir.nn != nil {
		match, err := reference.FamiliarMatch(pattern, ir.nn)
		if err != nil {
			err = errors.Join(ErrInvalidPattern, err)
		}

		return match, err
	}

	return false, nil
}

// String returns the string representation of the image reference.
func (ir *ImageReference) String() string {
	if ir.Protocol != "" && ir.Domain == "" {
		return ir.Path
	}

	if ir.Path == "" && ir.Digest != "" {
		return ir.Digest.String()
	}

	if ir.nn != nil {
		return ir.nn.String()
	}

	return ""
}

// SuggestContainerName generates a suggested container name based on the image reference.
func (ir *ImageReference) SuggestContainerName(suffix string) string {
	name := "untitled"
	if ir.Protocol != "" && ir.Domain == "" {
		name = string(ir.Protocol) + "-" + ir.String()[:shortIDLength]
	} else if ir.Path != "" {
		name = path.Base(ir.Path)
	}

	return name + "-" + suffix[:5] //revive:disable:add-constant
}

// Parse parses a raw image reference string and returns an ImageReference object.
func Parse(rawRef string) (*ImageReference, error) {
	imageRef := &ImageReference{}

	if dgst, err := digest.Parse(rawRef); err == nil {
		imageRef.Digest = dgst

		return imageRef, nil
	} else if dgst, err := digest.Parse("sha256:" + rawRef); err == nil {
		imageRef.Digest = dgst

		return imageRef, nil
	}

	var err error

	imageRef.nn, err = reference.ParseNormalizedNamed(rawRef)
	if err != nil {
		return imageRef, errors.Join(ErrInvalidImageReference, err)
	}

	if tg, ok := imageRef.nn.(reference.Tagged); ok {
		imageRef.ExplicitTag = tg.Tag()
	}

	if tg, ok := imageRef.nn.(reference.Named); ok {
		imageRef.nn = reference.TagNameOnly(tg)
		imageRef.Domain = reference.Domain(tg)
		imageRef.Path = reference.Path(tg)
	}

	if tg, ok := imageRef.nn.(reference.Tagged); ok {
		imageRef.Tag = tg.Tag()
	}

	if tg, ok := imageRef.nn.(reference.Digested); ok {
		imageRef.Digest = tg.Digest()
	}

	return imageRef, nil
}
