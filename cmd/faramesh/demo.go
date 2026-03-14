package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
	"github.com/faramesh/faramesh-core/internal/embedded"
)

var demoPolicyYAML = embedded.DemoPolicy

// demoScenario is a single synthetic tool call used by faramesh demo.
type demoScenario struct {
	label   string
	toolID  string
	args    map[string]any
	comment string
}

// The 5 canonical demo scenarios covering the most important governance classes.
var demoScenarios = []demoScenario{
	{
		label:   "get_exchange_rate",
		toolID:  "get_exchange_rate",
		args:    map[string]any{"from": "USD", "to": "SEK"},
		comment: "from=USD to=SEK",
	},
	{
		label:   "shell/run",
		toolID:  "shell/run",
		args:    map[string]any{"cmd": "rm -rf /tmp/build"},
		comment: `cmd="rm -rf /tmp/build"`,
	},
	{
		label:   "read_customer",
		toolID:  "read_customer",
		args:    map[string]any{"id": "cust_abc123"},
		comment: "id=cust_abc123",
	},
	{
		label:   "stripe/refund",
		toolID:  "stripe/refund",
		args:    map[string]any{"amount": float64(12000), "currency": "usd"},
		comment: "amount=$12,000",
	},
	{
		label:   "send_email",
		toolID:  "send_email",
		args: map[string]any{
			"subject":    "Hello",
			"recipients": makeRecipients(847),
		},
		comment: "recipients=847",
	},
}

var demoCmd = &cobra.Command{
	Use:   "demo",
	Short: "Run a synthetic agent demo — the 'docker run hello-world' moment",
	Long: `faramesh demo starts a synthetic agent against a pre-loaded policy set
and streams live authorization decisions to your terminal. Zero config. Zero
infrastructure. See PERMIT, DENY, and DEFER decisions in under 3 seconds.`,
	RunE: runDemo,
}

func runDemo(cmd *cobra.Command, args []string) error {
	// Build an in-memory pipeline — no disk, no socket, no infrastructure.
	doc, version, err := policy.LoadBytes(demoPolicyYAML)
	if err != nil {
		return fmt.Errorf("load demo policy: %w", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		return fmt.Errorf("compile demo policy: %w", err)
	}

	pipeline := core.NewPipeline(core.Config{
		Engine:   policy.NewAtomicEngine(engine),
		WAL:      &dpr.NullWAL{},
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	// Header.
	bold := color.New(color.Bold)
	dim := color.New(color.FgHiBlack)
	fmt.Println()
	bold.Println("Faramesh — Unified Agent Governance")
	dim.Println("Starting synthetic agent with demo policy...")
	fmt.Println()
	time.Sleep(300 * time.Millisecond)

	permitColor := color.New(color.FgGreen, color.Bold)
	denyColor := color.New(color.FgRed, color.Bold)
	deferColor := color.New(color.FgYellow, color.Bold)

	permit, deny, deferred := 0, 0, 0

	for _, scenario := range demoScenarios {
		// Small inter-call delay so output feels live, not batched.
		time.Sleep(350 * time.Millisecond)

		req := core.CanonicalActionRequest{
			CallID:           fmt.Sprintf("demo-%s", scenario.toolID),
			AgentID:          "demo-agent",
			SessionID:        "demo-session",
			ToolID:           scenario.toolID,
			Args:             scenario.args,
			Timestamp:        time.Now(),
			InterceptAdapter: "sdk",
		}

		decision := pipeline.Evaluate(req)

		ts := time.Now().Format("15:04:05")
		latency := fmt.Sprintf("latency=%dms", decision.Latency.Milliseconds())
		label := padRight(scenario.label, 22)
		comment := padRight(scenario.comment, 28)

		switch decision.Effect {
		case core.EffectPermit:
			permit++
			permitColor.Printf("[%s] PERMIT  ", ts)
			fmt.Printf("%s %s %s\n", label, comment, dim.Sprint(latency))
		case core.EffectDeny:
			deny++
			denyColor.Printf("[%s] DENY    ", ts)
			tag := ""
			if decision.RuleID != "" {
				tag = dim.Sprintf("policy=%s  %s", decision.RuleID, latency)
			} else if decision.ReasonCode != "" {
				tag = dim.Sprintf("scanner=%s  %s", decision.ReasonCode, latency)
			}
			fmt.Printf("%s %s %s\n", label, comment, tag)
		case core.EffectDefer:
			deferred++
			deferColor.Printf("[%s] DEFER   ", ts)
			tag := dim.Sprintf("awaiting approval  policy=%s  %s", decision.RuleID, latency)
			fmt.Printf("%s %s %s\n", label, comment, tag)
		case core.EffectShadow:
			dim.Printf("[%s] SHADOW  %s %s\n", ts, label, comment)
		}
	}

	// Summary.
	fmt.Println()
	dim.Printf("─────────────────────────────────────────────\n")
	total := len(demoScenarios)
	fmt.Printf("%d actions evaluated. ", total)
	permitColor.Printf("%d PERMIT", permit)
	fmt.Print("  ")
	denyColor.Printf("%d DENY", deny)
	fmt.Print("  ")
	deferColor.Printf("%d DEFER", deferred)
	fmt.Println()
	fmt.Println()
	fmt.Printf("Start governing your agent:\n")
	bold.Printf("  faramesh serve --policy payment.yaml\n")
	fmt.Printf("\nAuto-detect your environment:\n")
	bold.Printf("  faramesh init\n")
	fmt.Println()

	return nil
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func makeRecipients(n int) []any {
	r := make([]any, n)
	for i := range r {
		r[i] = fmt.Sprintf("user%d@example.com", i)
	}
	return r
}
