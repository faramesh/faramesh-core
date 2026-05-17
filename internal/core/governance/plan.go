package governance

import (
	"fmt"
	"os"
	"sort"
)

// PlanChange describes one difference between compiled stacks.
type PlanChange struct {
	Resource string
	Action   string
	Detail   string
}

// Plan compares the on-disk compiled artifact with a newly compiled stack.
func Plan(stackDir string, next *Compiled) ([]PlanChange, error) {
	if next == nil {
		return nil, fmt.Errorf("nil compiled stack")
	}
	prev, err := LoadCompiled(stackDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []PlanChange{{
				Resource: "stack",
				Action:   "create",
				Detail:   "initial apply (no prior governance.compiled.json)",
			}}, nil
		}
		return nil, err
	}
	var changes []PlanChange
	if prev.SourceSHA256 != next.SourceSHA256 {
		changes = append(changes, PlanChange{
			Resource: "governance",
			Action:   "update",
			Detail:   fmt.Sprintf("source hash %s → %s", shortHash(prev.SourceSHA256), shortHash(next.SourceSHA256)),
		})
	}
	if prev.Daemon.RuntimeMode != next.Daemon.RuntimeMode {
		changes = append(changes, PlanChange{
			Resource: "runtime.mode",
			Action:   "update",
			Detail:   fmt.Sprintf("%q → %q", prev.Daemon.RuntimeMode, next.Daemon.RuntimeMode),
		})
	}
	if prev.Daemon.SocketPath != next.Daemon.SocketPath {
		changes = append(changes, PlanChange{
			Resource: "runtime.socket",
			Action:   "update",
			Detail:   fmt.Sprintf("%q → %q", prev.Daemon.SocketPath, next.Daemon.SocketPath),
		})
	}
	if prev.Daemon.DataDir != next.Daemon.DataDir {
		changes = append(changes, PlanChange{
			Resource: "runtime.wal_dir",
			Action:   "update",
			Detail:   fmt.Sprintf("%q → %q", prev.Daemon.DataDir, next.Daemon.DataDir),
		})
	}
	if prev.PrimaryAgentID != next.PrimaryAgentID {
		changes = append(changes, PlanChange{
			Resource: "agent",
			Action:   "update",
			Detail:   fmt.Sprintf("primary agent %q → %q", prev.PrimaryAgentID, next.PrimaryAgentID),
		})
	}
	if providerSnapshotChanged(prev, next) {
		changes = append(changes, PlanChange{
			Resource: "providers",
			Action:   "update",
			Detail:   "credential broker configuration changed (daemon drain required)",
		})
	}
	if len(changes) == 0 {
		changes = append(changes, PlanChange{
			Resource: "stack",
			Action:   "noop",
			Detail:   "compiled configuration unchanged",
		})
	}
	sort.Slice(changes, func(i, j int) bool {
		return changes[i].Resource < changes[j].Resource
	})
	return changes, nil
}

func providerSnapshotChanged(a, b *Compiled) bool {
	if a == nil || b == nil {
		return true
	}
	return a.Daemon.VaultAddr != b.Daemon.VaultAddr ||
		a.Daemon.VaultToken != b.Daemon.VaultToken ||
		a.Daemon.AWSSecretsRegion != b.Daemon.AWSSecretsRegion ||
		a.Daemon.GCPSecretsProject != b.Daemon.GCPSecretsProject ||
		a.Daemon.AzureKeyVaultURL != b.Daemon.AzureKeyVaultURL
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
