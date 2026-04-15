package main

import (
	"fmt"
	"strings"

	"github.com/faramesh/faramesh-core/internal/hub"
)

func resolvePackRefForLocalInstall(root, ref string) (name, ver string, err error) {
	name, ver, err = hub.ParsePackRef(ref)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(ver) == "" {
		ver, err = latestInstalledVersion(root, name)
		if err != nil {
			return "", "", err
		}
	}
	return name, ver, nil
}

func emitInstalledPackLifecycleText(name, ver string, st hub.PackLifecycleStatus) {
	if !st.Installed {
		fmt.Printf("%s@%s is not installed\n", name, ver)
		return
	}
	mode := strings.TrimSpace(st.AppliedMode)
	if mode == "" {
		mode = "enforce"
	}
	trust := strings.TrimSpace(st.TrustTier)
	if trust == "" {
		trust = "unspecified"
	}
	head := "installed and enabled"
	if st.Disabled {
		head = "disabled"
	}
	fmt.Printf("%s@%s is %s\n", name, ver, head)
	fmt.Printf("Applied mode: %s\n", mode)
	fmt.Printf("Trust tier:   %s\n", trust)
	fmt.Printf("Policy:       %s\n", st.PolicyPath)
	if strings.TrimSpace(st.PolicyFPLPath) != "" {
		fmt.Printf("FPL:          %s\n", st.PolicyFPLPath)
	}
	if strings.TrimSpace(st.PolicyCompiledPath) != "" {
		fmt.Printf("Compiled:     %s\n", st.PolicyCompiledPath)
	}
	if st.Disabled {
		if strings.TrimSpace(st.DisabledPath) != "" {
			fmt.Printf("Disabled manifest: %s\n", st.DisabledPath)
		}
		if strings.TrimSpace(st.DisabledReason) != "" {
			fmt.Printf("Reason: %s\n", st.DisabledReason)
		}
		if strings.TrimSpace(st.DisabledAt) != "" {
			fmt.Printf("Disabled at: %s\n", st.DisabledAt)
		}
		return
	}
	if mode == "shadow" {
		fmt.Printf("Next: when ready for enforcement, run: faramesh pack enforce %s@%s\n", name, ver)
	}
}
