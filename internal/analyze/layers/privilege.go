package layers

import (
	"os"
)

type privilegeChecker struct{}

func newPrivilegeChecker() *privilegeChecker {
	return &privilegeChecker{}
}

func (c *privilegeChecker) check(entry FileEntry) *Assessment {
	// Check for SUID bit.
	if entry.Mode&os.ModeSetuid != 0 {
		return &Assessment{
			Code:     CodeCheckSuidGuid,
			Title:    Titles[CodeCheckSuidGuid],
			Level:    DefaultLevels[CodeCheckSuidGuid],
			Message:  "setuid file: " + entry.Mode.String() + " " + entry.Path,
			Filename: entry.Path,
		}
	}

	// Check for SGID bit.
	if entry.Mode&os.ModeSetgid != 0 {
		return &Assessment{
			Code:     CodeCheckSuidGuid,
			Title:    Titles[CodeCheckSuidGuid],
			Level:    DefaultLevels[CodeCheckSuidGuid],
			Message:  "setgid file: " + entry.Mode.String() + " " + entry.Path,
			Filename: entry.Path,
		}
	}

	return nil
}
