package proxy

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.uber.org/zap"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const policyConnectPermit = `
faramesh-version: "1.0"
agent-id: "proxy-connect-test"
default_effect: deny
rules:
  - id: allow-connect
    match:
      tool: "proxy/connect"
    effect: permit
`

func pipelineConnectPermit(t *testing.T) *core.Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(policyConnectPermit))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatal(err)
	}
	return core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
}

func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b := make([]byte, 256)
				n, err := c.Read(b)
				if err != nil || n == 0 {
					return
				}
				_, _ = c.Write(b[:n])
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestConnectProxyPermittedEcho(t *testing.T) {
	echoAddr := startEchoServer(t)

	srv := NewServer(pipelineConnectPermit(t), zap.NewNop(), WithConnectProxy(true))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHost := u.Host
	if !strings.Contains(proxyHost, ":") {
		proxyHost = net.JoinHostPort(proxyHost, "80")
	}

	conn, err := net.Dial("tcp", proxyHost)
	if err != nil {
		t.Fatal(err)
		defer conn.Close()
	}

	_, err = io.WriteString(conn, "CONNECT "+echoAddr+" HTTP/1.1\r\nHost: "+echoAddr+"\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("echo: got %q", buf[:n])
	}
}

func readUntilResponseHeadersEnd(br *bufio.Reader) (firstLine string, err error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	firstLine = strings.TrimSpace(line)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return firstLine, err
		}
		if line == "\r\n" {
			break
		}
	}
	return firstLine, nil
}

func TestConnectProxyDeniedByPolicy(t *testing.T) {
	echoAddr := startEchoServer(t)

	srv := NewServer(testPipeline(t), zap.NewNop(), WithConnectProxy(true))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHost := u.Host
	if !strings.Contains(proxyHost, ":") {
		proxyHost = net.JoinHostPort(proxyHost, "80")
	}

	conn, err := net.Dial("tcp", proxyHost)
	if err != nil {
		t.Fatal(err)
		defer conn.Close()
	}

	_, err = io.WriteString(conn, "CONNECT "+echoAddr+" HTTP/1.1\r\nHost: "+echoAddr+"\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body %s", resp.StatusCode, body)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("json: %v body %q", err, body)
	}
	if m["error"] != "connect denied" {
		t.Fatalf("expected connect denied: %+v", m)
	}
}
