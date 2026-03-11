// Package deferwork — batch approval for DEFER.
//
// When multiple agents trigger the same rule, their DEFERs can be grouped
// and approved/denied in a single action. This reduces approval fatigue
// for operators managing many concurrent agents.
//
// Batching logic:
//   - Group by: rule ID + tool pattern (configurable)
//   - Each batch gets a single approval decision
//   - Individual items in a batch can be overridden
//   - DPR records each item individually with batch_approval metadata
package deferwork

import (
	"fmt"
	"sync"
	"time"
)

// Batch represents a group of related DEFER items.
type Batch struct {
	BatchID     string          `json:"batch_id"`
	RuleID      string          `json:"rule_id"`
	ToolPattern string          `json:"tool_pattern"`
	Items       []*BatchItem    `json:"items"`
	CreatedAt   time.Time       `json:"created_at"`
	Deadline    time.Time       `json:"deadline"`
	Resolved    bool            `json:"resolved"`
	Decision    string          `json:"decision,omitempty"` // approved, denied, partial
}

// BatchItem is a single DEFER within a batch.
type BatchItem struct {
	Token    string `json:"token"`
	AgentID  string `json:"agent_id"`
	ToolID   string `json:"tool_id"`
	Reason   string `json:"reason"`
	Override string `json:"override,omitempty"` // empty = follow batch, "approved", "denied"
}

// BatchManager groups and manages batch approvals.
type BatchManager struct {
	mu       sync.RWMutex
	batches  map[string]*Batch    // batchID → batch
	tokenMap map[string]string    // token → batchID
	groupBy  func(toolID, ruleID string) string // grouping key function
	workflow *Workflow            // underlying workflow for resolution
}

// NewBatchManager creates a new batch manager.
func NewBatchManager(wf *Workflow) *BatchManager {
	return &BatchManager{
		batches:  make(map[string]*Batch),
		tokenMap: make(map[string]string),
		groupBy:  defaultGroupKey,
		workflow: wf,
	}
}

// Add adds a DEFER item to the appropriate batch, creating one if needed.
func (bm *BatchManager) Add(token, agentID, toolID, ruleID, reason string, deadline time.Time) string {
	groupKey := bm.groupBy(toolID, ruleID)

	bm.mu.Lock()
	defer bm.mu.Unlock()

	// Find existing open batch for this group key.
	var batch *Batch
	for _, b := range bm.batches {
		if !b.Resolved && b.RuleID == ruleID && bm.groupBy(b.ToolPattern, b.RuleID) == groupKey {
			batch = b
			break
		}
	}

	if batch == nil {
		batch = &Batch{
			BatchID:     fmt.Sprintf("batch-%s-%d", groupKey, time.Now().UnixNano()),
			RuleID:      ruleID,
			ToolPattern: toolID,
			CreatedAt:   time.Now(),
			Deadline:    deadline,
		}
		bm.batches[batch.BatchID] = batch
	}

	item := &BatchItem{
		Token:   token,
		AgentID: agentID,
		ToolID:  toolID,
		Reason:  reason,
	}
	batch.Items = append(batch.Items, item)
	bm.tokenMap[token] = batch.BatchID

	// Extend deadline if the new item has a later one.
	if deadline.After(batch.Deadline) {
		batch.Deadline = deadline
	}

	return batch.BatchID
}

// ApproveBatch approves all items in a batch.
func (bm *BatchManager) ApproveBatch(batchID, resolvedBy string) error {
	return bm.resolveBatch(batchID, true, resolvedBy)
}

// DenyBatch denies all items in a batch.
func (bm *BatchManager) DenyBatch(batchID, resolvedBy string) error {
	return bm.resolveBatch(batchID, false, resolvedBy)
}

func (bm *BatchManager) resolveBatch(batchID string, approved bool, resolvedBy string) error {
	bm.mu.Lock()
	batch, ok := bm.batches[batchID]
	if !ok {
		bm.mu.Unlock()
		return fmt.Errorf("batch %s not found", batchID)
	}
	if batch.Resolved {
		bm.mu.Unlock()
		return fmt.Errorf("batch %s already resolved", batchID)
	}
	batch.Resolved = true
	if approved {
		batch.Decision = "approved"
	} else {
		batch.Decision = "denied"
	}
	bm.mu.Unlock()

	// Resolve each item through the underlying workflow.
	for _, item := range batch.Items {
		itemApproved := approved
		if item.Override == "approved" {
			itemApproved = true
		} else if item.Override == "denied" {
			itemApproved = false
		}
		reason := fmt.Sprintf("batch:%s by %s", batchID, resolvedBy)
		if err := bm.workflow.Resolve(item.Token, itemApproved, reason); err != nil {
			// Item may have already expired — continue with others.
			continue
		}
	}
	return nil
}

// OverrideItem sets an individual override for an item within a batch.
func (bm *BatchManager) OverrideItem(token, decision string) error {
	if decision != "approved" && decision != "denied" {
		return fmt.Errorf("invalid override decision: %s", decision)
	}
	bm.mu.Lock()
	defer bm.mu.Unlock()
	batchID, ok := bm.tokenMap[token]
	if !ok {
		return fmt.Errorf("token %s not in any batch", token)
	}
	batch := bm.batches[batchID]
	for _, item := range batch.Items {
		if item.Token == token {
			item.Override = decision
			return nil
		}
	}
	return fmt.Errorf("token %s not found in batch %s", token, batchID)
}

// PendingBatches returns all unresolved batches.
func (bm *BatchManager) PendingBatches() []*Batch {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	var result []*Batch
	for _, b := range bm.batches {
		if !b.Resolved {
			result = append(result, b)
		}
	}
	return result
}

// BatchForToken returns the batch containing the given token.
func (bm *BatchManager) BatchForToken(token string) *Batch {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	batchID, ok := bm.tokenMap[token]
	if !ok {
		return nil
	}
	return bm.batches[batchID]
}

// Cleanup removes resolved batches older than maxAge.
func (bm *BatchManager) Cleanup(maxAge time.Duration) int {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for id, batch := range bm.batches {
		if batch.Resolved && batch.CreatedAt.Before(cutoff) {
			for _, item := range batch.Items {
				delete(bm.tokenMap, item.Token)
			}
			delete(bm.batches, id)
			removed++
		}
	}
	return removed
}

func defaultGroupKey(toolID, ruleID string) string {
	return ruleID + ":" + toolID
}
