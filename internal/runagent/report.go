package runagent

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/sandbox"
)

// Report captures enforcement layers applied to an agent child.
type Report struct {
	Profile      string
	Broker       bool
	StrippedKeys []string
	Layers       sandbox.PlatformLayers
	Skipped      map[string]string
}

// ReportFromEnv builds a report from environment (apply-generated agent.env).
func ReportFromEnv(profile string) Report {
	if profile == "" {
		profile = os.Getenv("FARAMESH_ENFORCE_PROFILE")
	}
	if profile == "" {
		profile = "auto"
	}
	broker := os.Getenv("FARAMESH_STRIP_AMBIENT") == "1"
	return Report{
		Profile: profile,
		Broker:  broker,
		Layers:  sandbox.ActivePlatformLayers(profile),
	}
}

func (r Report) Write(w io.Writer) {
	fmt.Fprintln(w, "Faramesh Enforcement Report")
	fmt.Fprintf(w, "  Host OS: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(w, "  Profile: %s\n", r.Profile)
	if r.Broker {
		fmt.Fprintf(w, "  Credential broker (stripped: %s)\n", strings.Join(r.StrippedKeys, ", "))
	} else {
		fmt.Fprintln(w, "  Credential broker: disabled")
	}
	fmt.Fprintln(w, "  Framework auto-patch (FARAMESH_AUTOLOAD): enabled")
	fmt.Fprintf(w, "  Trust level: %s\n", os.Getenv("FARAMESH_TRUST_LEVEL"))

	writeLayer := func(name string, active bool, skipReason string) {
		if active {
			fmt.Fprintf(w, "  %s\n", name)
			return
		}
		if skipReason != "" {
			fmt.Fprintf(w, "  %s (skipped)\n", name+" ("+skipReason+")")
			return
		}
		fmt.Fprintf(w, "  %s (skipped)\n", name)
	}

	minimal := r.Profile == "minimal" || r.Profile == "off"
	switch runtime.GOOS {
	case "linux":
		seccomp := r.Layers.Seccomp && !minimal
		landlock := r.Layers.Landlock && !minimal
		writeLayer("seccomp-BPF (immutable)", seccomp, r.Skipped["seccomp"])
		writeLayer("Landlock LSM (filesystem)", landlock, r.Skipped["landlock"])
		netns := os.Geteuid() == 0 && !minimal
		writeLayer("Network namespace (iptables)", netns, "requires root")
	case "darwin":
		seatbelt := r.Layers.Seatbelt && !minimal
		writeLayer("Seatbelt sandbox-exec (macOS)", seatbelt, r.Skipped["seatbelt"])
		writeLayer("Proxy env steering (HTTP/SOCKS)", r.Layers.NetworkProxy, "")
	default:
		writeLayer("OS syscall sandbox", false, runtime.GOOS)
	}
}
