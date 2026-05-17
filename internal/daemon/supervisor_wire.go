package daemon

import (
	"context"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/daemon/agentsupervisor"
)

func (d *Daemon) wireAgentSupervisor(doc *policy.Doc) error {
	stackDir := strings.TrimSpace(d.cfg.StackDir)
	if stackDir == "" {
		return nil
	}
	if !d.cfg.OSTier && strings.TrimSpace(d.cfg.SupervisedCommand) == "" {
		return nil
	}

	cliPath, err := agentsupervisor.ReadCLIPath(stackDir)
	if err != nil {
		cliPath, err = os.Executable()
		if err != nil {
			return err
		}
	}

	profile := strings.TrimSpace(d.cfg.AgentEnforceProfile)
	if d.cfg.OSTier && (profile == "" || profile == "off") {
		profile = "full"
	}
	if profile == "" {
		profile = "off"
	}

	proxyPort := d.cfg.ProxyPort
	if proxyPort == 0 {
		proxyPort = 18443
	}

	sup := agentsupervisor.New(d.log, agentsupervisor.Settings{
		StackDir:          stackDir,
		SocketPath:        d.cfg.SocketPath,
		CLIPath:           cliPath,
		EnforceProfile:    profile,
		StripAmbientCreds: d.cfg.StripAmbientCredentials,
		ProxyPort:         proxyPort,
	})
	d.agentSupervisor = sup
	if d.server != nil {
		d.server.SetAgentSupervisor(sup)
	}

	cmd := strings.TrimSpace(d.cfg.SupervisedCommand)
	if cmd == "" {
		return nil
	}
	agentID := strings.TrimSpace(d.cfg.PrimaryAgentID)
	if agentID == "" && doc != nil {
		agentID = doc.AgentID
	}
	_, err = sup.Launch(context.Background(), agentID, strings.Fields(cmd))
	if err != nil {
		return err
	}
	d.log.Info("supervised_command agent launched",
		zap.String("agent_id", agentID),
		zap.String("command", cmd),
	)
	return nil
}
