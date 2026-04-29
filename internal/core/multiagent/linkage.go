// Package multiagent — cross-agent DPR linkage.
//
// When one agent invokes another, the governance records must be linked
// bidirectionally: the outer DPR references the inner agent's governance
// DPR, and the inner DPR records which agent invoked it.
package multiagent

import (
	"sync"
)

// InvocationLink records the bidirectional DPR linkage between agents.
type InvocationLink struct {
	OuterAgentID string `json:"outer_agent_id"`
	OuterDPRID   string `json:"outer_dpr_id"`
	InnerAgentID string `json:"inner_agent_id"`
	InnerDPRID   string `json:"inner_dpr_id"`
	SessionID    string `json:"session_id"`
}

// LinkageManager tracks cross-agent DPR linkages.
type LinkageManager struct {
	mu    sync.Mutex
	links []InvocationLink
	// invoked: innerAgentID → link (who invoked me)
	invokedBy map[string][]InvocationLink
	// invocations: outerAgentID → link (who I invoked)
	invocations map[string][]InvocationLink
}

// NewLinkageManager creates a linkage manager.
func NewLinkageManager() *LinkageManager {
	return &LinkageManager{
		invokedBy:   make(map[string][]InvocationLink),
		invocations: make(map[string][]InvocationLink),
	}
}

// RecordLink registers a bidirectional DPR link between agents.
func (lm *LinkageManager) RecordLink(link InvocationLink) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.links = append(lm.links, link)
	lm.invokedBy[link.InnerAgentID] = append(lm.invokedBy[link.InnerAgentID], link)
	lm.invocations[link.OuterAgentID] = append(lm.invocations[link.OuterAgentID], link)
}

// InvokedBy returns the links where an agent was invoked by another.
func (lm *LinkageManager) InvokedBy(agentID string) []InvocationLink {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	links := lm.invokedBy[agentID]
	out := make([]InvocationLink, len(links))
	copy(out, links)
	return out
}

// Invocations returns the links where an agent invoked others.
func (lm *LinkageManager) Invocations(agentID string) []InvocationLink {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	links := lm.invocations[agentID]
	out := make([]InvocationLink, len(links))
	copy(out, links)
	return out
}

// ChainFromDPR returns the full invocation chain starting from a DPR record.
func (lm *LinkageManager) ChainFromDPR(dprID string) []InvocationLink {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	var chain []InvocationLink
	visited := make(map[string]bool)
	lm.collectChain(dprID, &chain, visited)
	return chain
}

func (lm *LinkageManager) collectChain(dprID string, chain *[]InvocationLink, visited map[string]bool) {
	if visited[dprID] {
		return
	}
	visited[dprID] = true

	for _, link := range lm.links {
		if link.OuterDPRID == dprID {
			*chain = append(*chain, link)
			lm.collectChain(link.InnerDPRID, chain, visited)
		}
	}
}

// AllLinks returns all recorded links.
func (lm *LinkageManager) AllLinks() []InvocationLink {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	out := make([]InvocationLink, len(lm.links))
	copy(out, lm.links)
	return out
}

// LinksForSession returns all links within a session.
func (lm *LinkageManager) LinksForSession(sessionID string) []InvocationLink {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	var out []InvocationLink
	for _, link := range lm.links {
		if link.SessionID == sessionID {
			out = append(out, link)
		}
	}
	return out
}
