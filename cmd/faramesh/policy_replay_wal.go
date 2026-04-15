package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/credential"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/multiagent"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const policyReplaySampleLimit = 10

type policyReplayDivergence struct {
	RecordID      string `json:"record_id"`
	ToolID        string `json:"tool_id"`
	OldEffect     string `json:"old_effect"`
	NewEffect     string `json:"new_effect"`
	OldReasonCode string `json:"old_reason_code"`
	NewReasonCode string `json:"new_reason_code"`
	ReplayMode    string `json:"replay_mode,omitempty"`
	Notes         string `json:"notes,omitempty"`
}

type policyReplaySummary struct {
	TotalRecords          int                      `json:"total_records_examined"`
	Divergences           int                      `json:"divergences"`
	EffectDivergences     int                      `json:"effect_divergences"`
	ReasonCodeDivergences int                      `json:"reason_code_divergences"`
	Samples               []policyReplayDivergence `json:"sample_divergences,omitempty"`
}

type policyReplayWALOptions struct {
	StrictReasonParity bool
	HMACKey            string
}

var (
	policyReplayWALPolicyPath    string
	policyReplayWALPath          string
	policyReplayWALLimit         int
	policyReplayWALMaxDivergence int
	policyReplayWALStrictReason  bool
	policyReplayWALHMACKey       string
)

var policyReplayWALCmd = &cobra.Command{
	Use:   "policy-replay",
	Short: "Counterfactually replay policy decisions from historical WAL records",
	RunE:  runPolicyReplayWALCommand,
}

func init() {
	policyReplayWALCmd.Flags().StringVar(&policyReplayWALPolicyPath, "policy", "", "path to policy file (YAML or FPL)")
	policyReplayWALCmd.Flags().StringVar(&policyReplayWALPath, "wal", "", "path to DPR WAL file")
	policyReplayWALCmd.Flags().IntVar(&policyReplayWALLimit, "limit", 0, "maximum number of records to replay (0 = all)")
	policyReplayWALCmd.Flags().IntVar(&policyReplayWALMaxDivergence, "max-divergence", -1, "fail if divergences exceed this threshold (-1 disables failure)")
	policyReplayWALCmd.Flags().BoolVar(&policyReplayWALStrictReason, "strict-reason-parity", false, "reserved for CLI compatibility; scanner/runtime deny parity now depends on persisted selector snapshots (legacy passthrough removed)")
	policyReplayWALCmd.Flags().StringVar(&policyReplayWALHMACKey, "dpr-hmac-key", "", "HMAC secret used to verify approval envelopes during replay")
	_ = policyReplayWALCmd.MarkFlagRequired("policy")
	_ = policyReplayWALCmd.MarkFlagRequired("wal")
	policyCmd.AddCommand(policyReplayWALCmd)
}

func runPolicyReplayWALCommand(cmd *cobra.Command, _ []string) error {
	summary, err := runPolicyReplayWALWithOptions(policyReplayWALPolicyPath, policyReplayWALPath, policyReplayWALLimit, policyReplayWALOptions{
		StrictReasonParity: policyReplayWALStrictReason,
		HMACKey:            policyReplayWALHMACKey,
	})
	if err != nil {
		return err
	}

	fmt.Printf("policy replay: %d record(s) examined, %d divergence(s) [effect=%d reason=%d]\n",
		summary.TotalRecords,
		summary.Divergences,
		summary.EffectDivergences,
		summary.ReasonCodeDivergences,
	)
	for _, sample := range summary.Samples {
		fmt.Printf("- record=%s tool=%s old=%s/%s new=%s/%s mode=%s",
			sample.RecordID,
			sample.ToolID,
			sample.OldEffect,
			sample.OldReasonCode,
			sample.NewEffect,
			sample.NewReasonCode,
			sample.ReplayMode,
		)
		if strings.TrimSpace(sample.Notes) != "" {
			fmt.Printf(" note=%q", sample.Notes)
		}
		fmt.Println()
	}
	if policyReplayWALMaxDivergence >= 0 && summary.Divergences > policyReplayWALMaxDivergence {
		return fmt.Errorf("policy replay divergences %d exceed threshold %d", summary.Divergences, policyReplayWALMaxDivergence)
	}
	return nil
}

func runPolicyReplayWAL(policyPath, walPath string, limit int) (policyReplaySummary, error) {
	return runPolicyReplayWALWithOptions(policyPath, walPath, limit, policyReplayWALOptions{})
}

func runPolicyReplayWALWithOptions(policyPath, walPath string, limit int, opts policyReplayWALOptions) (policyReplaySummary, error) {
	if strings.TrimSpace(policyPath) == "" {
		return policyReplaySummary{}, fmt.Errorf("--policy is required")
	}
	if strings.TrimSpace(walPath) == "" {
		return policyReplaySummary{}, fmt.Errorf("--wal is required")
	}
	if limit < 0 {
		return policyReplaySummary{}, fmt.Errorf("--limit must be >= 0")
	}

	doc, version, err := policy.LoadFile(policyPath)
	if err != nil {
		return policyReplaySummary{}, fmt.Errorf("load policy: %w", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		return policyReplaySummary{}, fmt.Errorf("compile policy: %w", err)
	}
	replayWorkflow := deferwork.NewWorkflow("")
	if key := []byte(opts.HMACKey); len(key) > 0 {
		replayWorkflow.SetApprovalHMACKey(key)
	}
	replayPipeline := core.NewPipeline(core.Config{
		Engine:           policy.NewAtomicEngine(engine),
		Sessions:         session.NewManager(),
		Defers:           replayWorkflow,
		CredentialRouter: newPolicyReplayCredentialRouter(),
		RoutingGovernor:  multiagent.NewRoutingGovernor(),
		HMACKey:          []byte(opts.HMACKey),
	})

	records, err := readRecordsFromWAL(walPath)
	if err != nil {
		return policyReplaySummary{}, fmt.Errorf("read --wal records: %w", err)
	}
	_ = opts.StrictReasonParity // CLI flag retained for compatibility; replay no longer uses legacy reason passthrough.

	replayRecords := records
	if limit > 0 && limit < len(records) {
		replayRecords = records[:limit]
	}

	summary := policyReplaySummary{TotalRecords: len(replayRecords)}
	for _, rec := range replayRecords {
		oldEffect := normalizeEffect(rec.Effect)
		oldReasonCode := reasons.Normalize(rec.ReasonCode)

		replayMode := "pipeline"
		replayNotes := ""
		newEffect, newReasonCode := replayDecisionFromPipeline(replayPipeline, replayWorkflow, rec)

		effectParity := oldEffect == newEffect
		reasonParity := oldReasonCode == newReasonCode
		if !effectParity {
			summary.EffectDivergences++
		}
		if !reasonParity {
			summary.ReasonCodeDivergences++
		}
		if effectParity && reasonParity {
			continue
		}
		summary.Divergences++
		if len(summary.Samples) < policyReplaySampleLimit {
			summary.Samples = append(summary.Samples, policyReplayDivergence{
				RecordID:      rec.RecordID,
				ToolID:        rec.ToolID,
				OldEffect:     oldEffect,
				NewEffect:     newEffect,
				OldReasonCode: oldReasonCode,
				NewReasonCode: newReasonCode,
				ReplayMode:    replayMode,
				Notes:         replayNotes,
			})
		}
	}
	return summary, nil
}

func replayDecisionFromPipeline(pip *core.Pipeline, wf *deferwork.Workflow, rec *dpr.Record) (string, string) {
	args := copyStringAnyMap(rec.SelectorSnapshot)
	if args == nil {
		args = map[string]any{}
	}

	agentID := strings.TrimSpace(rec.AgentID)
	if agentID == "" {
		agentID = "policy-replay-agent"
	}
	sessionID := strings.TrimSpace(rec.SessionID)
	if sessionID == "" {
		sessionID = "policy-replay-session"
	}
	callID := strings.TrimSpace(rec.RecordID)
	if callID == "" {
		callID = "policy-replay-" + strings.TrimSpace(rec.ToolID)
	}
	if strings.TrimSpace(rec.ApprovalEnvelope) != "" {
		callID += "-resume"
	}
	timestamp := rec.CreatedAt
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	req := core.CanonicalActionRequest{
		CallID:             callID,
		AgentID:            agentID,
		SessionID:          sessionID,
		ToolID:             strings.TrimSpace(rec.ToolID),
		Args:               args,
		Timestamp:          timestamp,
		InterceptAdapter:   strings.TrimSpace(rec.InterceptAdapter),
		ExecutionTimeoutMS: rec.ExecutionTimeoutMS,
	}
	if wf != nil {
		seedReplayApprovalResumeState(wf, req, rec)
	}
	d := pip.Evaluate(req)
	return normalizeEffect(string(d.Effect)), reasons.Normalize(d.ReasonCode)
}

func seedReplayApprovalResumeState(wf *deferwork.Workflow, req core.CanonicalActionRequest, rec *dpr.Record) {
	if wf == nil || strings.TrimSpace(rec.ApprovalEnvelope) == "" || !strings.HasSuffix(req.CallID, "-resume") {
		return
	}
	var env deferwork.ApprovalEnvelope
	if err := json.Unmarshal([]byte(rec.ApprovalEnvelope), &env); err != nil {
		return
	}
	for _, candidate := range replayResumeTokens(req) {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		ctx := deferwork.NewDeferContext(candidate, req.SessionID, "", copyStringAnyMap(req.Args))
		ctx.CreatedAt = time.Now().UTC()
		wf.StoreContext(ctx)
		_ = wf.RestoreResolution(candidate, deferwork.Resolution{
			Approved:     env.Approved,
			ApproverID:   env.ApproverID,
			Reason:       env.Reason,
			Status:       env.Status,
			ResolvedAt:   env.ResolvedAt,
			ModifiedArgs: copyStringAnyMap(env.ModifiedArgs),
			Envelope:     cloneReplayApprovalEnvelope(&env),
		})
	}
}

func cloneReplayApprovalEnvelope(env *deferwork.ApprovalEnvelope) *deferwork.ApprovalEnvelope {
	if env == nil {
		return nil
	}
	return &deferwork.ApprovalEnvelope{
		Token:        env.Token,
		ApproverID:   env.ApproverID,
		Approved:     env.Approved,
		Reason:       env.Reason,
		Status:       env.Status,
		ResolvedAt:   env.ResolvedAt,
		ModifiedArgs: copyStringAnyMap(env.ModifiedArgs),
		Signature:    env.Signature,
	}
}

func replayResumeTokens(req core.CanonicalActionRequest) []string {
	originalCallID := strings.TrimSuffix(req.CallID, "-resume")
	tokens := []string{core.DeterministicDeferToken(originalCallID, req.ToolID)}
	if replayTopologyInvokeTool(req.ToolID) {
		if target := replayExtractTargetAgentID(req.Args); target != "" {
			routeToken := fmt.Sprintf("%x", sha256.Sum256([]byte(originalCallID+req.ToolID+target)))[:8]
			if routeToken != tokens[0] {
				tokens = append(tokens, routeToken)
			}
		}
	}
	return tokens
}

func replayTopologyInvokeTool(toolID string) bool {
	if toolID == "multiagent/invoke_agent" || toolID == "invoke_agent" {
		return true
	}
	if strings.HasSuffix(toolID, "/invoke_agent") {
		return true
	}
	parts := strings.Split(strings.TrimSpace(toolID), "/")
	return len(parts) >= 2 && parts[len(parts)-2] == "invoke_agent"
}

func replayExtractTargetAgentID(args map[string]any) string {
	return replayExtractNestedString(args, "target_agent_id", "agent_id")
}

func replayExtractNestedString(args map[string]any, keys ...string) string {
	if args == nil {
		return ""
	}
	for _, key := range keys {
		if s, ok := args[key].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	for _, nestedKey := range []string{"params", "input", "arguments"} {
		if nested, ok := args[nestedKey].(map[string]any); ok {
			for _, key := range keys {
				if s, ok := nested[key].(string); ok && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
	}
	return ""
}

type policyReplayCredentialBroker struct{}

func (b *policyReplayCredentialBroker) Fetch(_ context.Context, req credential.FetchRequest) (*credential.Credential, error) {
	return &credential.Credential{
		Source:    b.Name(),
		Scope:     strings.TrimSpace(req.Scope),
		Revocable: false,
	}, nil
}

func (b *policyReplayCredentialBroker) Revoke(_ context.Context, _ *credential.Credential) error {
	return nil
}

func (b *policyReplayCredentialBroker) Name() string {
	return "policy_replay"
}

func newPolicyReplayCredentialRouter() *credential.Router {
	broker := &policyReplayCredentialBroker{}
	return credential.NewRouter([]credential.Broker{broker}, broker)
}

func replayEvalContext(rec *dpr.Record) policy.EvalContext {
	ctx := policy.EvalContext{
		Args: map[string]any{},
		Time: policy.TimeCtx{
			Hour:    rec.CreatedAt.UTC().Hour(),
			Weekday: normalizeWeekday(int(rec.CreatedAt.UTC().Weekday())),
			Month:   int(rec.CreatedAt.UTC().Month()),
			Day:     rec.CreatedAt.UTC().Day(),
		},
	}
	if rec.SelectorSnapshot != nil {
		ctx.Args = copyStringAnyMap(rec.SelectorSnapshot)
	}
	return ctx
}

func copyStringAnyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func normalizeEffect(effect string) string {
	return strings.ToUpper(strings.TrimSpace(effect))
}

func normalizeWeekday(day int) int {
	if day == 0 {
		return 7
	}
	return day
}
