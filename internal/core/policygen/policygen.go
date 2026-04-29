package policygen

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/toolinventory"
)

// Options configures deterministic starter policy generation.
type Options struct {
	AgentID string
	Now     time.Time
}

// Recommendation captures why a rule was proposed for an observed tool.
type Recommendation struct {
	ToolID         string   `json:"tool_id"`
	RecommendedFor string   `json:"recommended_for"`
	Effect         string   `json:"effect"`
	Risk           string   `json:"risk"`
	CoverageTier   string   `json:"coverage_tier,omitempty"`
	Reason         string   `json:"reason"`
	Tags           []string `json:"tags,omitempty"`
}

// Result is the full suggestion output for CLI and tests.
type Result struct {
	GeneratedAt      time.Time        `json:"generated_at"`
	ObservedTools    int              `json:"observed_tools"`
	TotalInvocations int64            `json:"total_invocations"`
	Warnings         []string         `json:"warnings,omitempty"`
	Recommendations  []Recommendation `json:"recommendations"`
	Doc              *policy.Doc      `json:"doc"`
}

type classification struct {
	Effect        string
	Risk          string
	Reason        string
	Tags          []string
	BlastRadius   string
	Reversibility string
	ShadowSafe    bool
}

// Generate converts observed tool inventory into a conservative starter policy.
func Generate(entries []toolinventory.Entry, opts Options) Result {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	agentID := strings.TrimSpace(opts.AgentID)
	if agentID == "" {
		agentID = "suggested-agent"
	}

	sorted := append([]toolinventory.Entry(nil), entries...)
	slices.SortFunc(sorted, func(a, b toolinventory.Entry) int { return strings.Compare(a.ToolID, b.ToolID) })

	doc := &policy.Doc{
		FarameshVersion: "1.0",
		AgentID:         agentID,
		DefaultEffect:   "deny",
		Tools:           map[string]policy.Tool{},
		Rules:           []policy.Rule{},
	}
	result := Result{
		GeneratedAt: now,
		Doc:         doc,
	}

	var (
		shellObserved bool
		totalCalls    int64
	)
	for _, entry := range sorted {
		if strings.TrimSpace(entry.ToolID) == "" {
			continue
		}
		shellObserved = shellObserved || strings.HasPrefix(strings.ToLower(entry.ToolID), "shell/")
		totalCalls += entry.TotalInvocations

		classified := classifyObservedTool(entry)
		doc.Tools[entry.ToolID] = policy.Tool{
			Tags:          append([]string(nil), classified.Tags...),
			BlastRadius:   classified.BlastRadius,
			Reversibility: classified.Reversibility,
			ShadowSafe:    classified.ShadowSafe,
		}
		doc.Rules = append(doc.Rules, policy.Rule{
			ID:     ruleIDForTool(classified.Effect, entry.ToolID),
			Match:  policy.Match{Tool: entry.ToolID, When: "true"},
			Effect: classified.Effect,
			Reason: classified.Reason,
		})
		result.Recommendations = append(result.Recommendations, Recommendation{
			ToolID:         entry.ToolID,
			RecommendedFor: entry.ToolID,
			Effect:         classified.Effect,
			Risk:           classified.Risk,
			CoverageTier:   strings.TrimSpace(entry.CoverageTier),
			Reason:         classified.Reason,
			Tags:           append([]string(nil), classified.Tags...),
		})
	}

	if shellObserved {
		doc.Rules = append([]policy.Rule{
			{
				ID: "deny-destructive-shell",
				Match: policy.Match{
					Tool: "shell/*",
					When: `args.cmd != nil && args.cmd matches "rm -rf|terraform destroy|shutdown|reboot|mkfs|dd if="`,
				},
				Effect: "deny",
				Reason: "destructive shell commands are denied by default",
			},
		}, doc.Rules...)
		result.Warnings = append(result.Warnings, "shell access observed; generated a destructive-shell deny guard before tool-specific rules")
	}

	if totalCalls > 0 {
		doc.Budget = &policy.Budget{
			MaxCalls: suggestedMaxCalls(totalCalls),
			OnExceed: "defer",
		}
	}

	result.ObservedTools = len(result.Recommendations)
	result.TotalInvocations = totalCalls
	if result.ObservedTools == 0 {
		result.Warnings = append(result.Warnings, "no observed tools found; generated policy will remain deny-by-default")
	}
	return result
}

// RenderYAML marshals the suggested policy document into installable YAML.
func RenderYAML(result Result) ([]byte, error) {
	if result.Doc == nil {
		return nil, fmt.Errorf("nil suggested policy document")
	}
	return yaml.Marshal(result.Doc)
}

func classifyObservedTool(entry toolinventory.Entry) classification {
	toolID := strings.ToLower(strings.TrimSpace(entry.ToolID))
	effect := "defer"
	risk := "medium"
	reason := "observed tool should start in review mode until behavior is validated"
	tags := []string{}
	blastRadius := "medium"
	reversibility := "unknown"
	shadowSafe := false

	switch {
	case onlyDenied(entry):
		effect = "deny"
		risk = "high"
		reason = "tool was only observed on deny paths; keep denied until explicitly reviewed"
		blastRadius = "high"
	case isDestructiveTool(toolID):
		effect = "deny"
		risk = "critical"
		reason = "destructive or irreversible tool should be denied by default"
		blastRadius = "high"
		reversibility = "irreversible"
	case isReadOnlyTool(toolID):
		effect = "permit"
		risk = "low"
		reason = "read-only informational tool is a safe starter permit"
		blastRadius = "low"
		reversibility = "reversible"
		shadowSafe = true
	case isHighRiskTool(toolID):
		effect = "defer"
		risk = "high"
		reason = "high-risk tool should require human review until rollout stabilizes"
		blastRadius = "high"
	}

	if isCredentialTool(toolID) {
		tags = append(tags, "credential:required", "credential:broker")
		if risk == "low" {
			risk = "high"
		}
		reason = "credential-bearing tool should use brokered secrets and human review"
		effect = "defer"
		blastRadius = "high"
	}

	switch strings.ToUpper(strings.TrimSpace(entry.CoverageTier)) {
	case "D", "E":
		if effect == "permit" {
			effect = "defer"
			risk = "medium"
			reason = "weakly governed tool path should start in defer mode despite low-risk shape"
		}
	}

	if isHighRiskTool(toolID) && !slices.Contains(tags, "risk:high") {
		tags = append(tags, "risk:high")
	}
	slices.Sort(tags)
	return classification{
		Effect:        effect,
		Risk:          risk,
		Reason:        reason,
		Tags:          tags,
		BlastRadius:   blastRadius,
		Reversibility: reversibility,
		ShadowSafe:    shadowSafe,
	}
}

func onlyDenied(entry toolinventory.Entry) bool {
	total := 0
	denied := 0
	for effect, count := range entry.Effects {
		total += count
		if strings.EqualFold(effect, "DENY") {
			denied += count
		}
	}
	return total > 0 && denied == total
}

func isReadOnlyTool(toolID string) bool {
	return strings.HasPrefix(toolID, "read_") ||
		strings.HasPrefix(toolID, "get_") ||
		strings.Contains(toolID, "/read") ||
		strings.Contains(toolID, "/get") ||
		strings.Contains(toolID, "/list") ||
		strings.Contains(toolID, "/query") ||
		strings.Contains(toolID, "/search") ||
		strings.Contains(toolID, "/describe") ||
		strings.HasPrefix(toolID, "search")
}

func isHighRiskTool(toolID string) bool {
	return strings.HasPrefix(toolID, "shell/") ||
		strings.Contains(toolID, "stripe/") ||
		strings.Contains(toolID, "payment/") ||
		strings.Contains(toolID, "refund") ||
		strings.Contains(toolID, "transfer") ||
		strings.Contains(toolID, "email/send") ||
		strings.Contains(toolID, "slack/post") ||
		strings.Contains(toolID, "file/write") ||
		strings.Contains(toolID, "db/update") ||
		strings.Contains(toolID, "db/insert") ||
		strings.Contains(toolID, "http/post") ||
		strings.Contains(toolID, "http/put") ||
		strings.Contains(toolID, "http/delete") ||
		strings.Contains(toolID, "aws/s3/put") ||
		strings.Contains(toolID, "lambda/invoke")
}

func isDestructiveTool(toolID string) bool {
	return strings.Contains(toolID, "/delete") ||
		strings.Contains(toolID, "/drop") ||
		strings.Contains(toolID, "/truncate") ||
		strings.Contains(toolID, "/destroy") ||
		strings.Contains(toolID, "/remove")
}

func isCredentialTool(toolID string) bool {
	return strings.Contains(toolID, "credential") ||
		strings.Contains(toolID, "secret") ||
		strings.Contains(toolID, "vault") ||
		strings.Contains(toolID, "token")
}

func ruleIDForTool(effect, toolID string) string {
	safe := strings.ToLower(strings.TrimSpace(toolID))
	replacer := strings.NewReplacer("/", "-", "_", "-", ".", "-", " ", "-")
	safe = replacer.Replace(safe)
	safe = strings.Trim(safe, "-")
	if safe == "" {
		safe = "tool"
	}
	return strings.ToLower(effect) + "-" + safe
}

func suggestedMaxCalls(totalInvocations int64) int64 {
	if totalInvocations <= 0 {
		return 50
	}
	if totalInvocations*2 < 50 {
		return 50
	}
	if totalInvocations*2 > 500 {
		return 500
	}
	return totalInvocations * 2
}
