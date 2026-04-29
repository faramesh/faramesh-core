package runtimeenv

import (
	"os"
	"testing"
)

func TestDeploymentKind(t *testing.T) {
	prev := map[string]string{
		"KUBERNETES_SERVICE_HOST":  os.Getenv("KUBERNETES_SERVICE_HOST"),
		"AWS_LAMBDA_FUNCTION_NAME": os.Getenv("AWS_LAMBDA_FUNCTION_NAME"),
		"K_SERVICE":                os.Getenv("K_SERVICE"),
		"K_REVISION":               os.Getenv("K_REVISION"),
		"CONTAINER_APP_NAME":       os.Getenv("CONTAINER_APP_NAME"),
		"CONTAINER_APP_REVISION":   os.Getenv("CONTAINER_APP_REVISION"),
	}
	defer func() {
		for k, v := range prev {
			_ = os.Setenv(k, v)
		}
	}()
	for k := range prev {
		_ = os.Unsetenv(k)
	}

	_ = os.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	if got := DeploymentKind(); got != "kubernetes" {
		t.Fatalf("got %q", got)
	}
	_ = os.Unsetenv("KUBERNETES_SERVICE_HOST")
	_ = os.Setenv("AWS_LAMBDA_FUNCTION_NAME", "fn")
	if got := DeploymentKind(); got != "aws_lambda" {
		t.Fatalf("got %q", got)
	}
}

func TestRegion_precedence(t *testing.T) {
	prev := map[string]string{
		"FARAMESH_REGION": os.Getenv("FARAMESH_REGION"),
		"AWS_REGION":      os.Getenv("AWS_REGION"),
	}
	defer func() {
		for k, v := range prev {
			_ = os.Setenv(k, v)
		}
	}()
	_ = os.Unsetenv("FARAMESH_REGION")
	_ = os.Unsetenv("AWS_REGION")
	if Region() != "" {
		t.Fatalf("expected empty, got %q", Region())
	}
	_ = os.Setenv("AWS_REGION", "eu-west-1")
	if got := Region(); got != "eu-west-1" {
		t.Fatalf("got %q", got)
	}
	_ = os.Setenv("FARAMESH_REGION", "override")
	if got := Region(); got != "override" {
		t.Fatalf("got %q", got)
	}
}

func TestKubernetesNamespace(t *testing.T) {
	prev := map[string]string{
		"FARAMESH_K8S_NAMESPACE": os.Getenv("FARAMESH_K8S_NAMESPACE"),
		"POD_NAMESPACE":          os.Getenv("POD_NAMESPACE"),
		"K8S_NAMESPACE":          os.Getenv("K8S_NAMESPACE"),
	}
	defer func() {
		for k, v := range prev {
			_ = os.Setenv(k, v)
		}
	}()
	for k := range prev {
		_ = os.Unsetenv(k)
	}
	if KubernetesNamespace() != "" {
		t.Fatal()
	}
	_ = os.Setenv("POD_NAMESPACE", "prod")
	if got := KubernetesNamespace(); got != "prod" {
		t.Fatalf("got %q", got)
	}
	_ = os.Setenv("FARAMESH_K8S_NAMESPACE", "override")
	if got := KubernetesNamespace(); got != "override" {
		t.Fatalf("got %q", got)
	}
}

func TestPolicyVarOverlay_hasFarameshVersion(t *testing.T) {
	ov := PolicyVarOverlay()
	v, ok := ov["faramesh_version"].(string)
	if !ok || v == "" {
		t.Fatalf("expected non-empty faramesh_version, got %+v", ov)
	}
}

func TestMergeDocVars_overlayWins(t *testing.T) {
	base := map[string]any{"a": 1, "deployment_kind": "should_lose"}
	ov := map[string]any{"deployment_kind": "kubernetes"}
	m := MergeDocVars(base, ov)
	if m["deployment_kind"] != "kubernetes" {
		t.Fatalf("%+v", m)
	}
	if m["a"] != 1 {
		t.Fatal()
	}
}
