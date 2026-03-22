// Package daemon provides gRPC service types for the A2 Local Daemon adapter.
// These types define the gRPC service contract without requiring protobuf
// code generation. In production, these would be generated from a .proto file.
package daemon

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	governMethod     = "/faramesh.daemon.v1.FarameshDaemon/Govern"
	killMethod       = "/faramesh.daemon.v1.FarameshDaemon/Kill"
	pushPolicyMethod = "/faramesh.daemon.v1.FarameshDaemon/PushPolicy"
)

const (
	// APIVersion is the canonical daemon API version.
	APIVersion = "1.0.0"
	// APIMajorVersion is the only accepted request major version.
	APIMajorVersion = 1
)

// GovernRequest is an incoming governance check from an agent process.
type GovernRequest struct {
	CallId             string `json:"call_id"`
	AgentId            string `json:"agent_id"`
	SessionId          string `json:"session_id"`
	ToolId             string `json:"tool_id"`
	ArgsJson           string `json:"args_json"` // JSON-encoded args
	ExecutionTimeoutMs int    `json:"execution_timeout_ms,omitempty"`
	WaitForApproval    bool   `json:"wait_for_approval"`
	ApiVersion         string `json:"api_version,omitempty"`
}

// GovernResponse is the governance decision returned to the agent.
type GovernResponse struct {
	Effect           string `json:"effect"`
	RuleId           string `json:"rule_id"`
	ReasonCode       string `json:"reason_code"`
	Reason           string `json:"reason"`
	DeferToken       string `json:"defer_token,omitempty"`
	PolicyVersion    string `json:"policy_version"`
	LatencyMs        int64  `json:"latency_ms"`
	DaemonApiVersion string `json:"daemon_api_version"`
}

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

// KillRequest triggers the kill switch for an agent.
type KillRequest struct {
	AgentId string `json:"agent_id"`
}

// KillResponse acknowledges the kill switch activation.
type KillResponse struct {
	Success bool `json:"success"`
}

// PushPolicyRequest submits raw policy YAML to the daemon for hot-apply.
type PushPolicyRequest struct {
	PolicyYaml string `json:"policy_yaml"`
	AdminToken string `json:"admin_token"`
}

// PushPolicyResponse reports the apply status for a pushed policy.
type PushPolicyResponse struct {
	Applied       bool     `json:"applied"`
	PolicyVersion string   `json:"policy_version,omitempty"`
	PolicyHash    string   `json:"policy_hash,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}

// FarameshDaemonServer is the interface for the gRPC daemon service.
type FarameshDaemonServer interface {
	Govern(context.Context, *GovernRequest) (*GovernResponse, error)
	Kill(context.Context, *KillRequest) (*KillResponse, error)
	PushPolicy(context.Context, *PushPolicyRequest) (*PushPolicyResponse, error)
}

// FarameshDaemonClient is a lightweight client for the daemon service.
// It uses JSON codec because service messages are handwritten Go structs.
type FarameshDaemonClient interface {
	Govern(ctx context.Context, in *GovernRequest, opts ...grpc.CallOption) (*GovernResponse, error)
	Kill(ctx context.Context, in *KillRequest, opts ...grpc.CallOption) (*KillResponse, error)
	PushPolicy(ctx context.Context, in *PushPolicyRequest, opts ...grpc.CallOption) (*PushPolicyResponse, error)
}

type farameshDaemonClient struct {
	cc grpc.ClientConnInterface
}

// NewFarameshDaemonClient returns a client bound to an existing gRPC connection.
func NewFarameshDaemonClient(cc grpc.ClientConnInterface) FarameshDaemonClient {
	return &farameshDaemonClient{cc: cc}
}

func (c *farameshDaemonClient) Govern(ctx context.Context, in *GovernRequest, opts ...grpc.CallOption) (*GovernResponse, error) {
	out := new(GovernResponse)
	callOpts := append([]grpc.CallOption{grpc.ForceCodec(jsonCodec{})}, opts...)
	if err := c.cc.Invoke(ctx, governMethod, in, out, callOpts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *farameshDaemonClient) Kill(ctx context.Context, in *KillRequest, opts ...grpc.CallOption) (*KillResponse, error) {
	out := new(KillResponse)
	callOpts := append([]grpc.CallOption{grpc.ForceCodec(jsonCodec{})}, opts...)
	if err := c.cc.Invoke(ctx, killMethod, in, out, callOpts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *farameshDaemonClient) PushPolicy(ctx context.Context, in *PushPolicyRequest, opts ...grpc.CallOption) (*PushPolicyResponse, error) {
	out := new(PushPolicyResponse)
	callOpts := append([]grpc.CallOption{grpc.ForceCodec(jsonCodec{})}, opts...)
	if err := c.cc.Invoke(ctx, pushPolicyMethod, in, out, callOpts...); err != nil {
		return nil, err
	}
	return out, nil
}

// Dial opens a local daemon gRPC connection with the JSON codec configured.
// For production TLS setups, pass additional options (e.g. custom creds).
func Dial(addr string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	base := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})),
	}
	base = append(base, opts...)
	return grpc.Dial(addr, base...)
}

// UnimplementedFarameshDaemonServer implements FarameshDaemonServer with
// unimplemented methods for forward compatibility.
type UnimplementedFarameshDaemonServer struct{}

func (UnimplementedFarameshDaemonServer) Govern(context.Context, *GovernRequest) (*GovernResponse, error) {
	return nil, grpc.Errorf(12, "method Govern not implemented") //nolint:staticcheck
}

func (UnimplementedFarameshDaemonServer) Kill(context.Context, *KillRequest) (*KillResponse, error) {
	return nil, grpc.Errorf(12, "method Kill not implemented") //nolint:staticcheck
}

func (UnimplementedFarameshDaemonServer) PushPolicy(context.Context, *PushPolicyRequest) (*PushPolicyResponse, error) {
	return nil, grpc.Errorf(12, "method PushPolicy not implemented") //nolint:staticcheck
}

// RegisterFarameshDaemonServer registers a FarameshDaemonServer with a gRPC server.
// In production this would be generated by protoc-gen-go-grpc.
func RegisterFarameshDaemonServer(s *grpc.Server, srv FarameshDaemonServer) {
	s.RegisterService(&FarameshDaemon_ServiceDesc, srv)
}

func _FarameshDaemon_Govern_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(GovernRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FarameshDaemonServer).Govern(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: governMethod,
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(FarameshDaemonServer).Govern(ctx, req.(*GovernRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FarameshDaemon_Kill_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(KillRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FarameshDaemonServer).Kill(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: killMethod,
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(FarameshDaemonServer).Kill(ctx, req.(*KillRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _FarameshDaemon_PushPolicy_Handler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(PushPolicyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FarameshDaemonServer).PushPolicy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: pushPolicyMethod,
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(FarameshDaemonServer).PushPolicy(ctx, req.(*PushPolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var FarameshDaemon_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "faramesh.daemon.v1.FarameshDaemon",
	HandlerType: (*FarameshDaemonServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Govern",
			Handler:    _FarameshDaemon_Govern_Handler,
		},
		{
			MethodName: "Kill",
			Handler:    _FarameshDaemon_Kill_Handler,
		},
		{
			MethodName: "PushPolicy",
			Handler:    _FarameshDaemon_PushPolicy_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "faramesh-daemon.proto",
}
