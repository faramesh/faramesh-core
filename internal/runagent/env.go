package runagent

import (
	"os"
	"strings"
)

var brokerSecretPrefixes = []string{
	"OPENAI_API_KEY=",
	"ANTHROPIC_API_KEY=",
	"AZURE_OPENAI_API_KEY=",
	"AWS_SECRET_ACCESS_KEY=",
	"AWS_ACCESS_KEY_ID=",
	"GOOGLE_API_KEY=",
	"HF_TOKEN=",
	"HUGGING_FACE_HUB_TOKEN=",
	"GITHUB_TOKEN=",
	"GH_TOKEN=",
	"NPM_TOKEN=",
	"PYPI_TOKEN=",
}

// StripBrokerSecrets removes ambient API keys from the environment when --broker is set.
func StripBrokerSecrets(env []string) (out []string, stripped []string) {
	out = make([]string, 0, len(env))
	for _, e := range env {
		upper := strings.ToUpper(e)
		removed := false
		for _, p := range brokerSecretPrefixes {
			if strings.HasPrefix(upper, strings.ToUpper(p)) {
				stripped = append(stripped, strings.TrimSuffix(p, "="))
				removed = true
				break
			}
		}
		if !removed {
			out = append(out, e)
		}
	}
	return out, stripped
}

// AugmentAgentEnv adds Faramesh runtime variables for governed agents.
func AugmentAgentEnv(env []string, agentID string) []string {
	set := func(k, v string) {
		prefix := k + "="
		for i, e := range env {
			if strings.HasPrefix(e, prefix) {
				env[i] = prefix + v
				return
			}
		}
		env = append(env, prefix+v)
	}
	if agentID != "" {
		set("FARAMESH_AGENT_ID", agentID)
	}
	set("FARAMESH_AUTOLOAD", "1")
	if strings.TrimSpace(os.Getenv("FARAMESH_TRUST_LEVEL")) == "" {
		set("FARAMESH_TRUST_LEVEL", "application")
	}
	return env
}
