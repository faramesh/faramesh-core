package launcher

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	providerv1 "github.com/faramesh/faramesh-core/proto/provider/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Sidecar manages a provider sidecar process and gRPC client.
type Sidecar struct {
	Name       string
	BinaryPath string
	SocketPath string
	cmd        *exec.Cmd
	conn       *grpc.ClientConn
	Client     providerv1.ProviderServiceClient
}

// Start launches the sidecar binary and dials its Unix socket.
func Start(ctx context.Context, name, binaryPath, stackDir string) (*Sidecar, error) {
	binaryPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return nil, err
	}
	if err := VerifyBinary(binaryPath, stackDir); err != nil {
		return nil, err
	}
	socketPath := filepath.Join(os.TempDir(), "faramesh-provider-"+sanitize(name)+".sock")
	_ = os.Remove(socketPath)

	cmd := exec.CommandContext(ctx, binaryPath, socketPath)
	cmd.Env = append(os.Environ(),
		"FARAMESH_PROVIDER_SOCKET="+socketPath,
		"FARAMESH_PROVIDER_NAME="+name,
	)
	configureProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start provider sidecar %q: %w", name, err)
	}

	sc := &Sidecar{Name: name, BinaryPath: binaryPath, SocketPath: socketPath, cmd: cmd}
	if err := waitForSocket(ctx, socketPath, 15*time.Second); err != nil {
		_ = sc.Stop()
		return nil, fmt.Errorf("provider %q socket: %w", name, err)
	}
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		_ = sc.Stop()
		return nil, err
	}
	sc.conn = conn
	sc.Client = providerv1.NewProviderServiceClient(conn)
	return sc, nil
}

// Stop terminates the sidecar and closes the gRPC connection.
func (s *Sidecar) Stop() error {
	if s == nil {
		return nil
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = terminateSidecar(s.cmd)
		_, _ = s.cmd.Process.Wait()
	}
	if s.SocketPath != "" {
		_ = os.Remove(s.SocketPath)
	}
	return nil
}

func waitForSocket(ctx context.Context, socketPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		conn, err := net.DialTimeout("unix", socketPath, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", socketPath)
}

func sanitize(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "provider"
	}
	return b.String()
}
