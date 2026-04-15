// Package daemon provides the daemon adapter compatibility layer over the
// generated gRPC API in `api/v1/faramesh.proto`.
package daemon

import (
	"fmt"
	"strconv"
	"strings"

	daemonv1 "github.com/faramesh/faramesh-core/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	governMethod     = daemonv1.FarameshDaemon_Govern_FullMethodName
	killMethod       = daemonv1.FarameshDaemon_Kill_FullMethodName
	pushPolicyMethod = daemonv1.FarameshDaemon_PushPolicy_FullMethodName
)

const (
	// APIVersion is the canonical daemon API version.
	APIVersion = "1.0.0"
	// APIMajorVersion is the only accepted request major version.
	APIMajorVersion = 1
)

type GovernRequest = daemonv1.GovernRequest
type GovernResponse = daemonv1.GovernResponse

func requestVersionMajor(version string) (int, error) {
	v := strings.TrimSpace(strings.TrimPrefix(version, "v"))
	if v == "" {
		return 0, fmt.Errorf("empty version")
	}
	parts := strings.Split(v, ".")
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return 0, fmt.Errorf("invalid major version %q", version)
	}
	return major, nil
}

type KillRequest = daemonv1.KillRequest
type KillResponse = daemonv1.KillResponse
type PushPolicyRequest = daemonv1.PushPolicyRequest
type PushPolicyResponse = daemonv1.PushPolicyResponse
type FarameshDaemonServer = daemonv1.FarameshDaemonServer
type FarameshDaemonClient = daemonv1.FarameshDaemonClient
type UnimplementedFarameshDaemonServer = daemonv1.UnimplementedFarameshDaemonServer

// NewFarameshDaemonClient returns a client bound to an existing gRPC connection.
func NewFarameshDaemonClient(cc grpc.ClientConnInterface) FarameshDaemonClient {
	return daemonv1.NewFarameshDaemonClient(cc)
}

// Dial opens a local daemon gRPC connection with the JSON codec configured.
// Generated protobuf messages are still sent through the JSON codec so existing
// local clients remain interoperable during the transition to formal protobuf
// definitions.
func Dial(addr string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	base := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
	}
	base = append(base, opts...)
	return grpc.Dial(addr, base...)
}

var RegisterFarameshDaemonServer = daemonv1.RegisterFarameshDaemonServer
