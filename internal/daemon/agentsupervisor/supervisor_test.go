package agentsupervisor_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/daemon/agentsupervisor"
	"go.uber.org/zap"
)

func TestSupervisorLaunchStop(t *testing.T) {
	if os.Getenv("CI") != "" && os.Getenv("FARAMESH_SUPERVISOR_E2E") == "" {
		t.Skip("supervisor integration test skipped in CI unless FARAMESH_SUPERVISOR_E2E=1")
	}
	dir := t.TempDir()
	log, _ := zap.NewDevelopment()
	sup := agentsupervisor.New(log, agentsupervisor.Settings{
		StackDir:       dir,
		SocketPath:     filepath.Join(dir, "sock"),
		EnforceProfile: "off",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	proc, err := sup.Launch(ctx, "test-agent", []string{"/bin/sh", "-c", "sleep 1"})
	if err != nil {
		t.Fatal(err)
	}
	if proc.PID <= 0 {
		t.Fatalf("expected pid, got %+v", proc)
	}
	list := sup.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 process, got %d", len(list))
	}
	_ = sup.Stop("test-agent")
}
