package remote

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core"
)

func TestDetectTransportRemoteURL(t *testing.T) {
	t.Setenv("FARAMESH_REMOTE_URL", "https://gov.example.com")
	t.Setenv("FARAMESH_SOCKET", "")
	tr, err := DetectTransport()
	if err != nil {
		t.Fatal(err)
	}
	if tr.Mode() != "remote" || tr.RemoteURL != "https://gov.example.com" {
		t.Fatalf("got %+v", tr)
	}
}

func TestDetectTransportSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "faramesh.sock")
	if err := os.WriteFile(sock, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FARAMESH_REMOTE_URL", "")
	t.Setenv("FARAMESH_BASE_URL", "")
	t.Setenv("FARAMESH_SOCKET", sock)
	tr, err := DetectTransport()
	if err != nil {
		t.Fatal(err)
	}
	if tr.Mode() != "socket" || tr.SocketPath != sock {
		t.Fatalf("got %+v", tr)
	}
}

func TestEvaluateSocketRequiresDaemon(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "missing.sock")
	t.Setenv("FARAMESH_SOCKET", sock)
	_, err := DetectTransport()
	if err == nil {
		t.Fatal("expected error for missing socket without remote URL")
	}
}

func TestTransportModeDefault(t *testing.T) {
	var tr *Transport
	if tr.Mode() != "socket" {
		t.Fatalf("nil transport mode: %q", tr.Mode())
	}
	_ = context.Background()
	_ = core.CanonicalActionRequest{}
}
