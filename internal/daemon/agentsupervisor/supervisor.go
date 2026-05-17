// Package agentsupervisor runs OS-sandboxed agent child processes under daemon control.
package agentsupervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/faramesh/faramesh-core/internal/runagent"
	"go.uber.org/zap"
)

// Settings mirrors compiled runtime agent-launch options.
type Settings struct {
	StackDir          string
	SocketPath        string
	CLIPath           string
	EnforceProfile    string
	StripAmbientCreds bool
	ProxyPort         int
}

// Process is a supervised agent child.
type Process struct {
	AgentID   string
	PID       int
	StartedAt time.Time
	Argv      []string
}

// Supervisor owns agent child processes (spawn, monitor, stop).
type Supervisor struct {
	mu       sync.Mutex
	log      *zap.Logger
	settings Settings
	procs    map[string]*exec.Cmd
	meta     map[string]Process
}

func New(log *zap.Logger, s Settings) *Supervisor {
	if s.ProxyPort == 0 {
		s.ProxyPort = 18443
	}
	if s.EnforceProfile == "" {
		s.EnforceProfile = "off"
	}
	return &Supervisor{
		log:      log,
		settings: s,
		procs:    make(map[string]*exec.Cmd),
		meta:     make(map[string]Process),
	}
}

// Launch starts argv under OS sandbox when configured. Idempotent per agentID (replaces prior).
func (s *Supervisor) Launch(ctx context.Context, agentID string, argv []string) (Process, error) {
	if len(argv) == 0 {
		return Process{}, fmt.Errorf("empty argv")
	}
	if agentID == "" {
		agentID = s.settings.StackDir
	}
	_ = s.Stop(agentID)

	env := os.Environ()
	env = append(env,
		fmt.Sprintf("FARAMESH_SOCKET=%s", s.settings.SocketPath),
		"FARAMESH_AUTOLOAD=1",
		fmt.Sprintf("FARAMESH_AGENT_ID=%s", agentID),
		fmt.Sprintf("FARAMESH_ENFORCE_PROFILE=%s", s.settings.EnforceProfile),
		fmt.Sprintf("FARAMESH_PROXY_PORT=%d", s.settings.ProxyPort),
	)
	if s.settings.StripAmbientCreds {
		env = append(env, "FARAMESH_STRIP_AMBIENT=1")
		env, _ = runagent.StripBrokerSecrets(env)
	}

	cli := s.settings.CLIPath
	if cli == "" {
		var err error
		cli, err = os.Executable()
		if err != nil {
			return Process{}, err
		}
	}

	var cmd *exec.Cmd
	profile := s.settings.EnforceProfile
	if profile != "off" && profile != "minimal" {
		args := append([]string{"__agent-exec", profile, s.settings.StackDir, fmt.Sprintf("%d", s.settings.ProxyPort), "--"}, argv...)
		cmd = exec.CommandContext(ctx, cli, args...)
	} else {
		cmd = exec.CommandContext(ctx, argv[0], argv[1:]...)
	}
	cmd.Env = env
	cmd.Dir = s.settings.StackDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return Process{}, err
	}

	meta := Process{
		AgentID:   agentID,
		PID:       cmd.Process.Pid,
		StartedAt: time.Now().UTC(),
		Argv:      append([]string(nil), argv...),
	}
	s.mu.Lock()
	s.procs[agentID] = cmd
	s.meta[agentID] = meta
	s.mu.Unlock()

	go s.waitReap(agentID, cmd)

	s.log.Info("supervised agent started",
		zap.String("agent_id", agentID),
		zap.Int("pid", meta.PID),
		zap.Strings("argv", argv),
		zap.String("enforce_profile", profile),
	)
	return meta, nil
}

func (s *Supervisor) waitReap(agentID string, cmd *exec.Cmd) {
	err := cmd.Wait()
	s.mu.Lock()
	delete(s.procs, agentID)
	s.mu.Unlock()
	if err != nil {
		s.log.Warn("supervised agent exited", zap.String("agent_id", agentID), zap.Error(err))
	} else {
		s.log.Info("supervised agent exited", zap.String("agent_id", agentID))
	}
}

// Stop terminates a supervised agent.
func (s *Supervisor) Stop(agentID string) error {
	s.mu.Lock()
	cmd, ok := s.procs[agentID]
	s.mu.Unlock()
	if !ok || cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Signal(os.Interrupt)
}

// List returns active supervised processes.
func (s *Supervisor) List() []Process {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Process, 0, len(s.meta))
	for _, p := range s.meta {
		out = append(out, p)
	}
	return out
}

// WriteCLIPath records the faramesh binary path for child re-exec.
func WriteCLIPath(stackDir, cliPath string) error {
	p := filepath.Join(stackDir, ".faramesh", "runtime", "cli.path")
	return os.WriteFile(p, []byte(cliPath+"\n"), 0o644)
}

// ReadCLIPath loads path written at apply.
func ReadCLIPath(stackDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(stackDir, ".faramesh", "runtime", "cli.path"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
