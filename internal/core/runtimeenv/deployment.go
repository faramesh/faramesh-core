// Package runtimeenv exposes process/runtime facts for policy conditions (vars.*)
// without importing adapters. Prefer this from core/pipeline; adapters may wrap the same API.
package runtimeenv

import (
	"os"
	"strconv"
	"strings"
)

// DeploymentKind returns a coarse label for where the governed process runs.
// Values: kubernetes, aws_lambda, gcp_cloud_run, azure_container_apps, unknown.
func DeploymentKind() string {
	switch {
	case os.Getenv("KUBERNETES_SERVICE_HOST") != "":
		return "kubernetes"
	case os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "":
		return "aws_lambda"
	case os.Getenv("K_SERVICE") != "" && os.Getenv("K_REVISION") != "":
		return "gcp_cloud_run"
	case os.Getenv("CONTAINER_APP_NAME") != "" && os.Getenv("CONTAINER_APP_REVISION") != "":
		return "azure_container_apps"
	default:
		return "unknown"
	}
}

// Region returns a coarse region identifier for policy when: vars.region.
// Precedence: FARAMESH_REGION, then common cloud env vars (AWS_*, GCP, Azure).
// Empty string if unset (policy may treat as unknown).
func Region() string {
	if s := strings.TrimSpace(os.Getenv("FARAMESH_REGION")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("AWS_REGION")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("AWS_DEFAULT_REGION")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_REGION")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("GCP_REGION")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("AZURE_REGION")); s != "" {
		return s
	}
	return ""
}

// KubernetesNamespace returns the pod namespace when running in Kubernetes, for policy when: vars.k8s_namespace.
// Precedence: FARAMESH_K8S_NAMESPACE, POD_NAMESPACE (common downward-API injection), K8S_NAMESPACE.
func KubernetesNamespace() string {
	if s := strings.TrimSpace(os.Getenv("FARAMESH_K8S_NAMESPACE")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("POD_NAMESPACE")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("K8S_NAMESPACE")); s != "" {
		return s
	}
	return ""
}

// PolicyVarOverlay returns runtime-injected entries merged into policy vars (overlay wins on key conflict).
func PolicyVarOverlay() map[string]any {
	ov := map[string]any{
		"deployment_kind":  DeploymentKind(),
		"runtime_kind":     RuntimeKind(),
		"region":           Region(),
		"k8s_namespace":    KubernetesNamespace(),
		"faramesh_version": BinaryVersion(),
	}
	// Optional operator hints (set by faramesh run or the host environment).
	if s := strings.TrimSpace(os.Getenv("FARAMESH_TRUST_LEVEL")); s != "" {
		ov["trust_level"] = s
	}
	if s := strings.TrimSpace(os.Getenv("FARAMESH_FRAMEWORK_HINT")); s != "" {
		ov["framework_hint"] = s
	}
	if s := strings.TrimSpace(os.Getenv("FARAMESH_AGENT_HARNESS")); s != "" {
		ov["agent_harness"] = s
	}
	if s := strings.TrimSpace(os.Getenv("FARAMESH_ADAPTER_LEVEL")); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			ov["adapter_level"] = n
		} else {
			ov["adapter_level"] = s
		}
	}
	return ov
}

// MergeDocVars merges YAML policy vars with runtime overlays (e.g. deployment_kind).
func MergeDocVars(docVars map[string]any, overlay map[string]any) map[string]any {
	out := make(map[string]any)
	for k, v := range docVars {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}
