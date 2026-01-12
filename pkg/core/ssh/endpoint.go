package ssh

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"

	"github.com/farcloser/quark/pkg/fault"
)

// Resolve determines the endpoint from a raw string, possibly using ssh config if requested.
//
//revive:disable:flag-parameter
func Resolve(endpoint string, withSSHConfig bool) (*Endpoint, error) {
	resolved := &Endpoint{
		Host: endpoint,
		Port: defaultSSHPort,
	}

	// Retrieve user
	if u, h, found := strings.Cut(endpoint, "@"); found {
		resolved.User = u
		resolved.Host = h
	}

	if resolved.User == "" && withSSHConfig {
		resolved.User = ssh_config.Get(endpoint, "User")
	}

	if resolved.User == "" {
		resolved.User = os.Getenv("USER")
	}

	if resolved.User == "" {
		resolved.User = os.Getenv("LOGNAME")
	}

	if resolved.User == "" {
		return nil, fmt.Errorf("%w: unable to resolve SSH user for host %s", fault.ErrInvalidArgument, endpoint)
	}

	// Retrieve hostname
	if withSSHConfig {
		if hostname := ssh_config.Get(endpoint, "Hostname"); hostname != "" {
			resolved.Host = hostname
		}
	}

	// Retrieve port
	var err error

	if withSSHConfig {
		if portStr := ssh_config.Get(endpoint, "Port"); portStr != "" {
			resolved.Port, err = strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid port in config %s", fault.ErrInvalidArgument, portStr)
			}
		}
	}

	return resolved, nil
}
