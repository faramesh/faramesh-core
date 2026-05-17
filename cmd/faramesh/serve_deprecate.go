package main

// serveDeprecationWarnings lists legacy flags set to non-default values.
func serveDeprecationWarnings() []string {
	var out []string
	if servePolicy != "" && servePolicy != "policy.fpl" {
		out = append(out, "--policy is deprecated; put agent policy in governance.fms")
	}
	if servePolicyURL != "" {
		out = append(out, "--policy-url is deprecated; use runtime { policy_url } in governance.fms")
	}
	if serveVaultAddr != "" || serveVaultToken != "" {
		out = append(out, "--vault-addr/--vault-token are deprecated; declare a provider block in governance.fms")
	}
	if serveDPRDSN != "" {
		out = append(out, "--dpr-dsn is deprecated; use runtime { backend, dsn } in governance.fms")
	}
	if serveProxyPort != 0 {
		out = append(out, "--proxy-port is deprecated; use agent enforcement { http_proxy_port } in governance.fms")
	}
	if serveMCPProxyPort != 0 {
		out = append(out, "--mcp-proxy-port is deprecated; use agent enforcement { mcp_proxy_port } in governance.fms")
	}
	if serveIntentClassifierURL != "" {
		out = append(out, "--intent-classifier-url is removed; do not use probabilistic classifiers in the enforcement path")
	}
	if len(out) == 0 {
		out = append(out, "`faramesh serve` is deprecated; use `faramesh apply` after authoring governance.fms")
	}
	return out
}
