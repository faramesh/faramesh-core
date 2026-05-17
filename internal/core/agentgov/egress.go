package agentgov

import (
	"net"
	"net/url"
	"strings"
)

// HostFromRequest extracts a destination host from common CAR argument shapes.
func HostFromRequest(args map[string]any) string {
	if args == nil {
		return ""
	}
	for _, key := range []string{"url", "host", "hostname", "endpoint", "base_url", "baseUrl"} {
		if v, ok := args[key]; ok {
			if h := hostFromValue(v); h != "" {
				return h
			}
		}
	}
	return ""
}

func hostFromValue(v any) string {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return ""
		}
		if strings.Contains(s, "://") {
			u, err := url.Parse(s)
			if err == nil && u.Host != "" {
				return strings.ToLower(strings.Split(u.Host, ":")[0])
			}
		}
		if strings.Contains(s, "/") {
			return ""
		}
		return strings.ToLower(strings.Split(s, ":")[0])
	default:
		return ""
	}
}

// AllowsEgress returns whether host is permitted by policy (default deny when allow list non-empty).
func (e *EgressPolicy) AllowsEgress(host string) bool {
	if e == nil {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return len(e.Allow) == 0
	}
	for _, d := range e.Deny {
		if matchHost(host, d) {
			return false
		}
	}
	if len(e.Allow) == 0 {
		return true
	}
	for _, a := range e.Allow {
		if matchHost(host, a) {
			return true
		}
	}
	return false
}

func matchHost(host, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(suffix, ".")
	}
	if host == pattern {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && pattern == host {
		return true
	}
	return false
}
