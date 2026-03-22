// Package env provides deployment hints for adapters (re-exports runtimeenv).
package env

import "github.com/faramesh/faramesh-core/internal/core/runtimeenv"

// DeploymentKind returns a coarse runtime label (see runtimeenv.DeploymentKind).
func DeploymentKind() string {
	return runtimeenv.DeploymentKind()
}

// Region returns the region for policy vars.region (see runtimeenv.Region).
func Region() string {
	return runtimeenv.Region()
}

// KubernetesNamespace returns policy vars.k8s_namespace (see runtimeenv.KubernetesNamespace).
func KubernetesNamespace() string {
	return runtimeenv.KubernetesNamespace()
}

// BinaryVersion returns policy vars.faramesh_version (see runtimeenv.BinaryVersion).
func BinaryVersion() string {
	return runtimeenv.BinaryVersion()
}

// RuntimeKind returns policy vars.runtime_kind (see runtimeenv.RuntimeKind).
func RuntimeKind() string {
	return runtimeenv.RuntimeKind()
}

// DetectEnvironment re-exports runtime environment detection for adapters / CLI.
func DetectEnvironment(workDir string) *runtimeenv.DetectedEnvironment {
	return runtimeenv.DetectEnvironment(workDir)
}
