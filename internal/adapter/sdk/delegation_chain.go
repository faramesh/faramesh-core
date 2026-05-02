package sdk

import (
	"strings"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/delegate"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

// resolveDelegationChain turns a request's optional delegation token into a
// principal.DelegationChain that the policy engine can consume.
//
// Returns:
//   - (chain, nil) when the token is valid and refers to the calling agent.
//   - (nil, nil)   when no token was presented.
//   - (nil, deny)  when the token is malformed, revoked, expired, or refers
//     to a different agent. Callers must short-circuit with the returned
//     Decision; the request never reaches the pipeline.
func (s *Server) resolveDelegationChain(req governRequest) (*principal.DelegationChain, *core.Decision) {
	token := strings.TrimSpace(req.DelegationToken)
	if token == "" {
		return nil, nil
	}
	if s.delegate == nil {
		return nil, &core.Decision{
			Effect:     core.EffectDeny,
			ReasonCode: reasons.DelegationTokenInvalid,
			Reason:     "delegation token presented but delegate service is not configured",
		}
	}

	res := s.delegate.Verify(token)
	if !res.Valid {
		return nil, &core.Decision{
			Effect:     core.EffectDeny,
			ReasonCode: reasons.DelegationTokenInvalid,
			Reason:     "delegation token rejected: " + res.Reason,
		}
	}

	stored, ok := s.delegate.Inspect(token)
	if !ok {
		return nil, &core.Decision{
			Effect:     core.EffectDeny,
			ReasonCode: reasons.DelegationTokenInvalid,
			Reason:     "delegation token not found in store",
		}
	}
	if stored.ToAgent != req.AgentID {
		return nil, &core.Decision{
			Effect:     core.EffectDeny,
			ReasonCode: reasons.DelegationTokenAgentMismatch,
			Reason:     "delegation token recipient does not match calling agent",
		}
	}

	chain := s.delegate.Chain(req.AgentID)
	links := make([]principal.DelegationLink, 0, len(chain)+1)
	for _, g := range chain {
		links = append(links, delegationLinkFromGrant(g))
	}
	// Ensure the leaf link reflects the agent itself when the walk does not
	// already terminate at it (defensive: Chain returns root→leaf grants where
	// each grant's ToAgent is the next agent; the final ToAgent should equal
	// req.AgentID).
	return &principal.DelegationChain{Links: links}, nil
}

func delegationLinkFromGrant(g delegate.Grant) principal.DelegationLink {
	scope := splitScopeForLink(g.Scope)
	return principal.DelegationLink{
		AgentID:          g.ToAgent,
		IdentityVerified: true,
		DelegatedAt:      g.IssuedAt.Unix(),
		Scope:            scope,
		Depth:            g.ChainDepth,
	}
}

func splitScopeForLink(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
