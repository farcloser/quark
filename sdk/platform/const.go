package platform

import (
	"github.com/farcloser/quark/internal/types"
)

type Platform = types.Platform

var (
	AMD64              = types.AMD64
	ARM64              = types.ARM64
	NoExplicitPlatform = types.NoExplicitPlatform
)
