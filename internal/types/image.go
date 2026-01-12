package types

import (
	"fmt"
)

type Image struct {
	Registry *RegistryCredentials
	Path     string
	Tag      string
	Digest   Digest
}

func (image *Image) String() string {
	if image.Registry == nil {
		panic("images must have an associated registry")
	}

	ret := fmt.Sprintf("%s/%s:%s", image.Registry.Domain, image.Path, image.Tag)
	if image.Digest != "" {
		ret += fmt.Sprintf("@%s", image.Digest)
	}

	return ret
}
