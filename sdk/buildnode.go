package sdk

import (
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// BuildNodeOpts contains configuration options for creating a build node.
type BuildNodeOpts struct {
	Name     string   // Required - node name
	Endpoint string   // Required - SSH endpoint (IP, hostname, or SSH config alias)
	Platform Platform // Required - build platform (e.g., PlatformAMD64, PlatformARM64)
}

// NewBuildNode creates a new BuildNode from the provided arguments.
func NewBuildNode(args *BuildNodeOpts) (*BuildNode, error) {
	endpoint := strings.TrimSpace(args.Endpoint)
	if endpoint == "" {
		return nil, ErrBuildNodeEndpointRequired
	}

	if args.Platform == (Platform{}) {
		return nil, ErrBuildNodePlatformRequired
	}

	return &BuildNode{
		name:     args.Name,
		endpoint: endpoint,
		platform: args.Platform,
		log:      log.Logger.With().Str("buildnode", args.Name).Logger(),
	}, nil
}

// BuildNode represents an SSH-accessible buildkit node.
type BuildNode struct {
	name     string
	endpoint string
	platform Platform
	log      zerolog.Logger
}
