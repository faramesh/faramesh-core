package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

// CompileOptions configures compilation.
type CompileOptions struct {
	CheckEnv bool
	Offline  bool
}

// Compile validates and builds a Compiled artifact from the governance AST.
func Compile(doc *ast.Document, stackDir string, source []byte, opts CompileOptions) (*Compiled, []Diagnostic, error) {
	diags := Check(doc, CheckOptions{RequireEnv: opts.CheckEnv})
	if HasErrors(diags) {
		return nil, diags, fmt.Errorf("governance check failed")
	}
	if err := ResolveImports(doc, opts.Offline); err != nil {
		diags = append(diags, Diagnostic{
			Severity: SeverityError,
			Location: doc.SourcePath,
			What:     "import resolution failed",
			Why:      err.Error(),
			Fix:      "Pin imports to github.com/faramesh/faramesh-registry/.../name@version or use faramesh check --offline",
		})
		return nil, diags, err
	}
	if err := RecordProviderImports(doc); err != nil {
		diags = append(diags, Diagnostic{
			Severity: SeverityError,
			Location: doc.SourcePath,
			What:     "provider import resolution failed",
			Why:      err.Error(),
			Fix:      "Pin provider imports to github.com/faramesh/faramesh-registry/providers/.../name@version",
		})
		return nil, diags, err
	}

	policyFPL, agentID, err := MaterializePolicyFPL(doc)
	if err != nil {
		return nil, diags, err
	}
	policyPath := PolicyPath(stackDir)
	if err := os.WriteFile(policyPath, []byte(policyFPL), 0o644); err != nil {
		return nil, diags, err
	}
	if _, _, loadErr := policy.LoadFile(policyPath); loadErr != nil {
		diags = append(diags, Diagnostic{
			Severity: SeverityError,
			Location: doc.SourcePath,
			What:     "materialized policy failed runtime validation",
			Why:      loadErr.Error(),
			Fix:      "Fix agent rules and budgets in governance.fms.",
		})
		return nil, diags, fmt.Errorf("policy validation: %w", loadErr)
	}
	snap, err := daemonSnapshotFromAST(doc, stackDir, policyPath)
	if err != nil {
		return nil, diags, err
	}
	pools := BudgetPoolsFromDocument(doc)
	snap.BudgetPools = pools

	sum := sha256.Sum256(source)
	compiled := &Compiled{
		Version:        compiledFormatVersion,
		StackDir:       stackDir,
		SourcePath:     doc.SourcePath,
		SourceSHA256:   hex.EncodeToString(sum[:]),
		CompiledAt:     time.Now().UTC(),
		PolicyFPL:      policyFPL,
		PrimaryAgentID: agentID,
		Providers:      providersCompiledFromAST(doc),
		Agents:         AgentRuntimeFromDocument(doc),
		BudgetPools:    pools,
		Daemon:         snap,
	}
	return compiled, diags, nil
}

func providersCompiledFromAST(doc *ast.Document) []ProviderCompiled {
	if doc == nil || len(doc.Providers) == 0 {
		return nil
	}
	out := make([]ProviderCompiled, 0, len(doc.Providers))
	for name, p := range doc.Providers {
		pc := ProviderCompiled{
			Name:   name,
			Type:   p.Type,
			Source: p.Source,
			Config: providerConfigMapResolved(p),
		}
		out = append(out, pc)
	}
	return out
}

func valueString(v ast.Value, resolveEnv bool) string {
	switch v.Kind {
	case ast.ValueEnv:
		if resolveEnv {
			if val := os.Getenv(v.EnvVar); val != "" {
				return val
			}
		}
		return "env(\"" + v.EnvVar + "\")"
	default:
		return v.Display()
	}
}

func daemonSnapshotFromAST(doc *ast.Document, stackDir, policyPath string) (DaemonSnapshot, error) {
	snap := DaemonSnapshot{
		PolicyPath: policyPath,
		DataDir:    defaultDataDir(stackDir, doc.Runtime),
		SocketPath: defaultSocket(doc.Runtime),
		LogLevel:   "info",
		RuntimeMode: "enforce",
	}
	if doc.Runtime != nil {
		rt := doc.Runtime
		if v := strings.TrimSpace(rt.Mode); v != "" {
			snap.RuntimeMode = v
		}
		if v := strings.TrimSpace(rt.LogLevel); v != "" {
			snap.LogLevel = v
		}
		if v := strings.TrimSpace(rt.WALDir); v != "" {
			snap.DataDir = absOrJoin(stackDir, v)
		}
		if v := strings.TrimSpace(rt.Socket); v != "" {
			snap.SocketPath = v
		}
		if rt.GRPCPort > 0 {
			snap.GRPCPort = rt.GRPCPort
		}
		if v := strings.TrimSpace(rt.DSN); v != "" {
			snap.DPRDSN = v
		}
		if v := strings.TrimSpace(rt.SessionDSN); v != "" {
			snap.RedisURL = v
		}
		if v := strings.TrimSpace(rt.DeferBackend); v != "" {
			snap.DeferBackend = v
		}
		if v := strings.TrimSpace(rt.DeferRedisPrefix); v != "" {
			snap.DeferRedisPrefix = v
		}
		snap.RequireGovernanceBootstrap = rt.RequireGovernanceBeforeNet
		if v := strings.TrimSpace(rt.OTLP); v != "" {
			snap.OTLPEnabled = true
			snap.OTLPEndpoint = v
		}
		snap.TenantID = strings.TrimSpace(rt.TenantID)
		snap.DPRSigner = strings.TrimSpace(rt.DPRSigner)
		snap.DPRKMSProvider = strings.TrimSpace(rt.DPRKMSProvider)
		snap.DPRKMSKeyRef = strings.TrimSpace(rt.DPRKMSKeyRef)
		snap.GovernToolResponses = rt.GovernToolResponses
		snap.ImmutableConfig = rt.ImmutableConfig
		snap.OSTier = rt.OSTier
		snap.StripAmbientCredentials = rt.StripAmbientCredentials
		snap.AgentEnforceProfile = strings.TrimSpace(rt.AgentEnforceProfile)
		snap.SupervisedCommand = strings.TrimSpace(rt.SupervisedCommand)
	}
	if snap.DPRKMSProvider == "" {
		snap.DPRKMSProvider = firstKMSProviderName(doc)
	}
	for _, p := range doc.Providers {
		mergeProviderIntoSnapshot(&snap, p)
	}
	for _, id := range doc.Identities {
		if id != nil && strings.EqualFold(id.Type, "spiffe") {
			if v := strings.TrimSpace(id.Socket); v != "" {
				snap.SPIFFESocketPath = v
			}
		}
	}
	return snap, nil
}

func mergeProviderIntoSnapshot(snap *DaemonSnapshot, p *ast.Provider) {
	if p == nil {
		return
	}
	typ := strings.ToLower(strings.TrimSpace(p.Type))
	switch typ {
	case "vault":
		snap.VaultAddr = resolveValue(p.Config["addr"])
		snap.VaultToken = resolveValue(p.Config["token"])
		if v := resolveValue(p.Config["mount"]); v != "" {
			snap.VaultMount = v
		}
		if v := resolveValue(p.Config["namespace"]); v != "" {
			snap.VaultNamespace = v
		}
	case "aws-sm", "aws_secrets", "aws":
		if v := resolveValue(p.Config["region"]); v != "" {
			snap.AWSSecretsRegion = v
		}
	case "gcp-sm", "gcp":
		if v := resolveValue(p.Config["project"]); v != "" {
			snap.GCPSecretsProject = v
		}
	case "azure-kv", "azure":
		snap.AzureKeyVaultURL = resolveValue(p.Config["vault_url"])
		snap.AzureTenantID = resolveValue(p.Config["tenant_id"])
		snap.AzureClientID = resolveValue(p.Config["client_id"])
		snap.AzureClientSecret = resolveValue(p.Config["client_secret"])
	}
}

func resolveValue(v ast.Value) string {
	switch v.Kind {
	case ast.ValueEnv:
		return os.Getenv(v.EnvVar)
	case ast.ValueString:
		return v.String
	case ast.ValueIdent:
		return v.String
	default:
		return v.Display()
	}
}

func defaultDataDir(stackDir string, rt *ast.Runtime) string {
	base := filepath.Join(stackDir, "faramesh-wal")
	if rt != nil && strings.TrimSpace(rt.WALDir) != "" {
		base = absOrJoin(stackDir, rt.WALDir)
	}
	if rt != nil {
		if tid := strings.TrimSpace(rt.TenantID); tid != "" {
			base = filepath.Join(base, sanitizePathSegment(tid))
		}
	}
	return base
}

func sanitizePathSegment(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "..", "")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	if s == "" {
		return "default"
	}
	return s
}

func firstKMSProviderName(doc *ast.Document) string {
	if doc == nil {
		return ""
	}
	for name, p := range doc.Providers {
		if p == nil {
			continue
		}
		for _, cap := range p.Capabilities {
			if strings.EqualFold(cap, "kms") {
				return name
			}
		}
		typ := strings.ToLower(strings.TrimSpace(p.Type))
		if typ == "kms" || typ == "kms-dev" || typ == "dev-kms" {
			return name
		}
	}
	return ""
}

func defaultSocket(rt *ast.Runtime) string {
	if rt != nil && strings.TrimSpace(rt.Socket) != "" {
		return rt.Socket
	}
	return sdk.SocketPath
}
