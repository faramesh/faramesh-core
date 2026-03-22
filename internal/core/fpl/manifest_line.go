package fpl

import (
	"fmt"
	"strconv"
	"strings"
)

// scanManifestLines splits FPL source into topology statements (manifest … lines) and remaining rule text.
func scanManifestLines(src string) (topo []TopoStatement, rulesSrc string, err error) {
	var ruleLines []string
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "manifest ") {
			st, e := parseManifestLine(line)
			if e != nil {
				return nil, "", fmt.Errorf("%w: %q", e, line)
			}
			topo = append(topo, st)
			continue
		}
		ruleLines = append(ruleLines, line)
	}
	return topo, strings.Join(ruleLines, "\n"), nil
}

func parseManifestLine(line string) (TopoStatement, error) {
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != "manifest" {
		return TopoStatement{}, fmt.Errorf("expected manifest line")
	}
	switch f[1] {
	case "orchestrator":
		if len(f) != 5 || f[3] != "undeclared" {
			return TopoStatement{}, fmt.Errorf("manifest orchestrator: want manifest orchestrator <id> undeclared deny|defer")
		}
		pol := strings.ToLower(f[4])
		if pol != "deny" && pol != "defer" {
			return TopoStatement{}, fmt.Errorf("manifest orchestrator: undeclared policy must be deny or defer")
		}
		id, err := manifestToken(f[2])
		if err != nil {
			return TopoStatement{}, err
		}
		return TopoStatement{Kind: TopoOrchestrator, OrchID: id, UndeclaredPolicy: pol}, nil

	case "grant":
		if len(f) != 7 && len(f) != 8 {
			return TopoStatement{}, fmt.Errorf("manifest grant: want manifest grant <orch> to <target> max <n> [approval]")
		}
		if f[3] != "to" || f[5] != "max" {
			return TopoStatement{}, fmt.Errorf("manifest grant: want manifest grant <orch> to <target> max <n> [approval]")
		}
		orch, err := manifestToken(f[2])
		if err != nil {
			return TopoStatement{}, err
		}
		tgt, err := manifestToken(f[4])
		if err != nil {
			return TopoStatement{}, err
		}
		n, err := strconv.Atoi(f[6])
		if err != nil || n < 0 {
			return TopoStatement{}, fmt.Errorf("manifest grant: invalid max %q", f[6])
		}
		reqAppr := false
		if len(f) == 8 {
			if strings.ToLower(f[7]) != "approval" {
				return TopoStatement{}, fmt.Errorf("manifest grant: expected approval as final token")
			}
			reqAppr = true
		}
		return TopoStatement{
			Kind:             TopoAllow,
			AllowOrchID:      orch,
			TargetAgentID:    tgt,
			MaxPerSession:    n,
			RequiresApproval: reqAppr,
		}, nil

	default:
		return TopoStatement{}, fmt.Errorf("unknown manifest kind %q", f[1])
	}
}

func manifestToken(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty id")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return strings.TrimSuffix(strings.TrimPrefix(s, `"`), `"`), nil
	}
	return s, nil
}
