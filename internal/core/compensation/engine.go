// Package compensation implements tool action reversibility classification
// and compensating action execution. When a previously-PERMIT'd tool call
// needs to be undone (e.g. after detecting a breach, or upon human review),
// the compensation engine looks up the reversal tool and executes it.
//
// This implements Layer 14 (Compensation & Reversibility) from the
// Faramesh architecture spec.
package compensation

import (
	"fmt"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/policy"
)

// Classification of tool reversibility.
type Classification string

const (
	// Irreversible actions cannot be undone (e.g., email sent, data deleted).
	Irreversible Classification = "irreversible"

	// Reversible actions can be automatically reversed (e.g., feature flag toggle).
	Reversible Classification = "reversible"

	// Compensatable actions can't be reversed but have a compensating action
	// (e.g., refund for a charge, credit for a debit).
	Compensatable Classification = "compensatable"
)

// CompensationRequest is a request to compensate a previously-PERMIT'd action.
type CompensationRequest struct {
	// OriginalRecordID is the DPR record ID of the original PERMIT decision.
	OriginalRecordID string `json:"original_record_id"`

	// OriginalToolID is the tool that was originally called.
	OriginalToolID string `json:"original_tool_id"`

	// OriginalArgs are the arguments from the original call.
	OriginalArgs map[string]any `json:"original_args"`

	// Reason explains why compensation is being triggered.
	Reason string `json:"reason"`

	// RequestedBy is the identity requesting compensation.
	RequestedBy string `json:"requested_by"`

	// RequestedAt is when compensation was requested.
	RequestedAt time.Time `json:"requested_at"`
}

// CompensationResult is the outcome of a compensation attempt.
type CompensationResult struct {
	// Status is the compensation outcome.
	Status CompensationStatus `json:"status"`

	// CompensationToolID is the tool called for compensation.
	CompensationToolID string `json:"compensation_tool_id,omitempty"`

	// CompensationArgs are the args passed to the compensation tool.
	CompensationArgs map[string]any `json:"compensation_args,omitempty"`

	// Error is set when compensation fails.
	Error string `json:"error,omitempty"`

	// ExecutedAt is when compensation was executed.
	ExecutedAt time.Time `json:"executed_at"`
}

// CompensationStatus is the outcome state.
type CompensationStatus string

const (
	StatusExecuted     CompensationStatus = "executed"
	StatusFailed       CompensationStatus = "failed"
	StatusNotSupported CompensationStatus = "not_supported"
	StatusExpired      CompensationStatus = "expired"
)

// Engine looks up compensation metadata from the policy and builds
// compensation tool calls.
type Engine struct {
	compensationMap map[string]policy.CompensationMeta
	toolMeta        map[string]policy.Tool
}

// NewEngine creates a compensation engine from the policy's compensation
// and tools declarations.
func NewEngine(doc *policy.Doc) *Engine {
	e := &Engine{
		compensationMap: make(map[string]policy.CompensationMeta),
		toolMeta:        make(map[string]policy.Tool),
	}
	if doc.Compensation != nil {
		for toolID, meta := range doc.Compensation {
			e.compensationMap[toolID] = meta
		}
	}
	if doc.Tools != nil {
		for toolID, tool := range doc.Tools {
			e.toolMeta[toolID] = tool
		}
	}
	return e
}

// Classify returns the reversibility classification for a tool.
func (e *Engine) Classify(toolID string) Classification {
	if t, ok := e.toolMeta[toolID]; ok {
		switch t.Reversibility {
		case "reversible":
			return Reversible
		case "compensatable":
			return Compensatable
		case "irreversible":
			return Irreversible
		}
	}
	// Check if compensation metadata exists.
	if _, ok := e.compensationMap[toolID]; ok {
		return Compensatable
	}
	// Default to irreversible (safe assumption).
	return Irreversible
}

// BuildCompensation creates the compensation tool call args from the
// original action's args using the policy-defined arg_mapping.
func (e *Engine) BuildCompensation(req CompensationRequest) (*CompensationResult, error) {
	meta, ok := e.compensationMap[req.OriginalToolID]
	if !ok {
		return &CompensationResult{
			Status:     StatusNotSupported,
			Error:      fmt.Sprintf("no compensation defined for tool %q", req.OriginalToolID),
			ExecutedAt: time.Now(),
		}, nil
	}

	// Build compensation args from the mapping.
	compArgs := make(map[string]any)
	for compArgName, sourceExpr := range meta.ArgMapping {
		// sourceExpr is a simple dot-path into the original args.
		// e.g., "charge_id" → original_args["charge_id"]
		val, ok := resolveArgPath(req.OriginalArgs, sourceExpr)
		if !ok {
			return &CompensationResult{
				Status:     StatusFailed,
				Error:      fmt.Sprintf("arg mapping %q: source %q not found in original args", compArgName, sourceExpr),
				ExecutedAt: time.Now(),
			}, nil
		}
		compArgs[compArgName] = val
	}

	return &CompensationResult{
		Status:             StatusExecuted,
		CompensationToolID: meta.CompensationTool,
		CompensationArgs:   compArgs,
		ExecutedAt:         time.Now(),
	}, nil
}

// CanCompensate returns true if compensation is defined for this tool.
func (e *Engine) CanCompensate(toolID string) bool {
	_, ok := e.compensationMap[toolID]
	return ok
}

// resolveArgPath resolves a dot-path expression against a map.
// e.g., "payment.charge_id" resolves args["payment"]["charge_id"].
func resolveArgPath(args map[string]any, path string) (any, bool) {
	parts := splitPath(path)
	var current any = args
	for _, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func splitPath(path string) []string {
	var parts []string
	current := ""
	for _, c := range path {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
