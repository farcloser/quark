package layers

import (
	"bufio"
	"bytes"
	"strings"
)

const (
	passwdFile = "etc/passwd"
	groupFile  = "etc/group"
)

type identityChecker struct{}

func newIdentityChecker() *identityChecker {
	return &identityChecker{}
}

func (c *identityChecker) check(entry FileEntry) []*Assessment {
	switch entry.Path {
	case passwdFile:
		return c.checkPasswd(entry)
	case groupFile:
		return c.checkGroup(entry)
	default:
		return nil
	}
}

// checkPasswd checks for duplicate UIDs in /etc/passwd.
func (c *identityChecker) checkPasswd(entry FileEntry) []*Assessment {
	if entry.Content == nil {
		return nil
	}

	var assessments []*Assessment

	uidMap := make(map[string]struct{})

	scanner := bufio.NewScanner(bytes.NewReader(entry.Content))
	for scanner.Scan() {
		line := scanner.Text()

		// Format: username:x:uid:gid:...
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}

		username := fields[0]
		uid := fields[2]

		if _, exists := uidMap[uid]; exists {
			assessments = append(assessments, &Assessment{
				Code:     CodeAvoidDuplicateUserGroup,
				Title:    Titles[CodeAvoidDuplicateUserGroup],
				Level:    DefaultLevels[CodeAvoidDuplicateUserGroup],
				Message:  "Duplicate UID " + uid + ": username " + username,
				Filename: entry.Path,
			})
		}

		uidMap[uid] = struct{}{}
	}

	return assessments
}

// checkGroup checks for duplicate GIDs in /etc/group.
func (c *identityChecker) checkGroup(entry FileEntry) []*Assessment {
	if entry.Content == nil {
		return nil
	}

	var assessments []*Assessment

	gidMap := make(map[string]struct{})

	scanner := bufio.NewScanner(bytes.NewReader(entry.Content))
	for scanner.Scan() {
		line := scanner.Text()

		// Format: groupname:x:gid:members
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}

		groupname := fields[0]
		gid := fields[2]

		if _, exists := gidMap[gid]; exists {
			assessments = append(assessments, &Assessment{
				Code:     CodeAvoidDuplicateUserGroup,
				Title:    Titles[CodeAvoidDuplicateUserGroup],
				Level:    DefaultLevels[CodeAvoidDuplicateUserGroup],
				Message:  "Duplicate GID " + gid + ": groupname " + groupname,
				Filename: entry.Path,
			})
		}

		gidMap[gid] = struct{}{}
	}

	return assessments
}
