// Package security implements production deployment invariant checks.
package security

import (
	"fmt"
	"os"
	"os/user"
	"strings"
)

const (
	DaemonUser = "faramesh"
	AgentUser  = "faramesh-agent"
)

// UIDCheckResult summarizes UID separation readiness.
type UIDCheckResult struct {
	CurrentUser   string
	DaemonUserOK  bool
	AgentUserOK   bool
	SeparationOK  bool
	Warnings      []string
}

// CheckUIDSeparation inspects local users for production daemon/agent separation.
func CheckUIDSeparation() UIDCheckResult {
	out := UIDCheckResult{}
	if u, err := user.Current(); err == nil {
		out.CurrentUser = u.Username
	}
	_, errDaemon := user.Lookup(DaemonUser)
	out.DaemonUserOK = errDaemon == nil
	agent, errAgent := user.Lookup(AgentUser)
	out.AgentUserOK = errAgent == nil
	if out.DaemonUserOK && out.AgentUserOK {
		if g, err := user.LookupGroup(DaemonUser); err == nil && g != nil {
			if _, err := user.LookupGroupId(g.Gid); err == nil {
				if strings.Contains(agent.Gid, g.Gid) || agentGidInGroup(agent, DaemonUser) {
					out.Warnings = append(out.Warnings, fmt.Sprintf("user %q must not be in group %q", AgentUser, DaemonUser))
				} else {
					out.SeparationOK = true
				}
			}
		} else {
			out.SeparationOK = true
		}
	}
	if u, err := user.Current(); err == nil && u.Username == "root" {
		out.Warnings = append(out.Warnings, "running as root; production daemon should run as user "+DaemonUser)
	}
	return out
}

func agentGidInGroup(agent *user.User, groupName string) bool {
	gids, err := agent.GroupIds()
	if err != nil {
		return false
	}
	grp, err := user.LookupGroup(groupName)
	if err != nil {
		return false
	}
	for _, gid := range gids {
		if gid == grp.Gid {
			return true
		}
	}
	return false
}

// EnforceUIDSeparation returns an error when require is true and invariants fail.
func EnforceUIDSeparation(require bool) error {
	res := CheckUIDSeparation()
	if !require {
		return nil
	}
	if !res.DaemonUserOK {
		return fmt.Errorf("production requires system user %q (create with: useradd -r -s /sbin/nologin %s)", DaemonUser, DaemonUser)
	}
	if os.Getuid() == 0 && res.CurrentUser == "root" {
		return fmt.Errorf("refusing to start daemon as root with --require-uid-separation; run faramesh apply as user %q", DaemonUser)
	}
	if !res.SeparationOK && res.AgentUserOK {
		return fmt.Errorf("UID separation failed: agent user %q must not share group %q with the daemon", AgentUser, DaemonUser)
	}
	return nil
}
