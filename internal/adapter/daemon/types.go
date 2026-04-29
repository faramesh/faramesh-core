// Package daemon provides the daemon adapter gRPC contract.
package daemon

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
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

type GovernRequest struct {
	CallId             string `json:"call_id,omitempty"`
	AgentId            string `json:"agent_id,omitempty"`
	SessionId          string `json:"session_id,omitempty"`
	ToolId             string `json:"tool_id,omitempty"`
	ArgsJson           string `json:"args_json,omitempty"`
	PrincipalToken     string `json:"principal_token,omitempty"`
	ExecutionTimeoutMs int32  `json:"execution_timeout_ms,omitempty"`
	WaitForApproval    bool   `json:"wait_for_approval,omitempty"`
	ApiVersion         string `json:"api_version,omitempty"`
}

type GovernResponse struct {
	Effect           string `json:"effect,omitempty"`
	RuleId           string `json:"rule_id,omitempty"`
	ReasonCode       string `json:"reason_code,omitempty"`
	Reason           string `json:"reason,omitempty"`
	DeferToken       string `json:"defer_token,omitempty"`
	PolicyVersion    string `json:"policy_version,omitempty"`
	LatencyMs        int64  `json:"latency_ms,omitempty"`
	DaemonApiVersion string `json:"daemon_api_version,omitempty"`
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

type KillRequest struct {
	AgentId string `json:"agent_id,omitempty"`
}

type KillResponse struct {
	Success bool `json:"success,omitempty"`
}

type PushPolicyRequest struct {
	PolicyYaml string `json:"policy_yaml,omitempty"`
	AdminToken string `json:"admin_token,omitempty"`
}

type PushPolicyResponse struct {
	Applied       bool     `json:"applied,omitempty"`
	PolicyVersion string   `json:"policy_version,omitempty"`
	PolicyHash    string   `json:"policy_hash,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}

type FarameshDaemonServer interface {
	Govern(context.Context, *GovernRequest) (*GovernResponse, error)
	Kill(context.Context, *KillRequest) (*KillResponse, error)
	PushPolicy(context.Context, *PushPolicyRequest) (*PushPolicyResponse, error)
	mustEmbedUnimplementedFarameshDaemonServer()
}

type FarameshDaemonClient interface {
	Govern(ctx context.Context, in *GovernRequest, opts ...grpc.CallOption) (*GovernResponse, error)
	Kill(ctx context.Context, in *KillRequest, opts ...grpc.CallOption) (*KillResponse, error)
	PushPolicy(ctx context.Context, in *PushPolicyRequest, opts ...grpc.CallOption) (*PushPolicyResponse, error)
}

type UnimplementedFarameshDaemonServer struct{}

func (UnimplementedFarameshDaemonServer) Govern(context.Context, *GovernRequest) (*GovernResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method Govern not implemented")
}

func (UnimplementedFarameshDaemonServer) Kill(context.Context, *KillRequest) (*KillResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method Kill not implemented")
}

func (UnimplementedFarameshDaemonServer) PushPolicy(context.Context, *PushPolicyRequest) (*PushPolicyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method PushPolicy not implemented")
}

func (UnimplementedFarameshDaemonServer) mustEmbedUnimplementedFarameshDaemonServer() {}
func (UnimplementedFarameshDaemonServer) testEmbeddedByValue()                        {}

type farameshDaemonClient struct {
	cc grpc.ClientConnInterface
}

// NewFarameshDaemonClient returns a client bound to an existing gRPC connection.
func NewFarameshDaemonClient(cc grpc.ClientConnInterface) FarameshDaemonClient {
	return &farameshDaemonClient{cc: cc}
}

func (c *farameshDaemonClient) Govern(ctx context.Context, in *GovernRequest, opts ...grpc.CallOption) (*GovernResponse, error) {
	out := new(GovernResponse)
	if err := c.cc.Invoke(ctx, governMethod, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *farameshDaemonClient) Kill(ctx context.Context, in *KillRequest, opts ...grpc.CallOption) (*KillResponse, error) {
	out := new(KillResponse)
	if err := c.cc.Invoke(ctx, killMethod, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *farameshDaemonClient) PushPolicy(ctx context.Context, in *PushPolicyRequest, opts ...grpc.CallOption) (*PushPolicyResponse, error) {
	out := new(PushPolicyResponse)
	if err := c.cc.Invoke(ctx, pushPolicyMethod, in, out, opts...); err != nil {
		return nil, err
	}
	return out, nil
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

func RegisterFarameshDaemonServer(s grpc.ServiceRegistrar, srv FarameshDaemonServer) {
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&farameshDaemonServiceDesc, srv)
}

func _farameshDaemonGovernHandler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
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
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FarameshDaemonServer).Govern(ctx, req.(*GovernRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _farameshDaemonKillHandler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
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
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FarameshDaemonServer).Kill(ctx, req.(*KillRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _farameshDaemonPushPolicyHandler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
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
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FarameshDaemonServer).PushPolicy(ctx, req.(*PushPolicyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var farameshDaemonServiceDesc = grpc.ServiceDesc{
	ServiceName: "faramesh.daemon.v1.FarameshDaemon",
	HandlerType: (*FarameshDaemonServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Govern", Handler: _farameshDaemonGovernHandler},
		{MethodName: "Kill", Handler: _farameshDaemonKillHandler},
		{MethodName: "PushPolicy", Handler: _farameshDaemonPushPolicyHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/v1/faramesh.proto",
}
