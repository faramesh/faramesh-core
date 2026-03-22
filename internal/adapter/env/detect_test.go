package env

import "testing"

func TestDeploymentKindDelegates(t *testing.T) {
	if DeploymentKind() == "" {
		t.Fatal()
	}
}
