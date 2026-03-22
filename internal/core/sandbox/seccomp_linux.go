//go:build linux

package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	// SYS_SECCOMP is not in Go's syscall package; amd64 syscall number.
	sysSeccomp = 317
)

// SeccompProfile is an OCI-compatible seccomp profile derived from policy.
type SeccompProfile struct {
	DefaultAction string         `json:"defaultAction"`
	Syscalls      []SeccompEntry `json:"syscalls"`
}

type SeccompEntry struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// GenerateSeccompProfile builds a seccomp-BPF allowlist from sandbox config.
// Allowed syscalls come from the policy; everything else is ERRNO'd.
func GenerateSeccompProfile(cfg *SandboxConfig) *SeccompProfile {
	p := &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
	}

	allowed := cfg.AllowedSyscalls
	if len(allowed) == 0 {
		allowed = defaultAgentSyscalls()
	}
	p.Syscalls = []SeccompEntry{
		{Names: allowed, Action: "SCMP_ACT_ALLOW"},
	}
	return p
}

// WriteSeccompProfile serializes the profile to a JSON file for use with
// container runtimes or direct seccomp(2) loading.
func WriteSeccompProfile(p *SeccompProfile, path string) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal seccomp profile: %w", err)
	}
	return os.WriteFile(path, b, 0o600)
}

// InstallSeccompFilter installs a minimal seccomp-BPF filter using prctl(2).
// Once installed, the filter is IMMUTABLE for the lifetime of the process
// and inherited by all child processes. This is the strongest enforcement —
// even root cannot remove it.
//
// This should be called by faramesh run just before execve() of the child.
func InstallSeccompFilter(cfg *SandboxConfig) error {
	allowed := cfg.AllowedSyscalls
	if len(allowed) == 0 {
		allowed = defaultAgentSyscalls()
	}

	nrs := make(map[uint32]bool, len(allowed))
	for _, name := range allowed {
		if nr, ok := syscallNumber(name); ok {
			nrs[nr] = true
		}
	}

	filter := buildBPFFilter(nrs)
	prog := syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	// PR_SET_NO_NEW_PRIVS is required before seccomp installation.
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL,
		uintptr(38), // PR_SET_NO_NEW_PRIVS
		1, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %v", errno)
	}

	// SECCOMP_SET_MODE_FILTER = 1
	if _, _, errno := syscall.RawSyscall(uintptr(sysSeccomp),
		1, // SECCOMP_SET_MODE_FILTER
		0, // flags
		uintptr(unsafe.Pointer(&prog))); errno != 0 {
		return fmt.Errorf("seccomp(SECCOMP_SET_MODE_FILTER): %v", errno)
	}
	return nil
}

// buildBPFFilter generates a classic BPF program that allows only the listed
// syscall numbers and returns EPERM for everything else.
func buildBPFFilter(allowed map[uint32]bool) []syscall.SockFilter {
	// BPF_LD+BPF_W+BPF_ABS: load syscall number from seccomp_data.nr (offset 0)
	prog := []syscall.SockFilter{
		{Code: 0x20, K: 0}, // LD [0] — load arch
		// We skip arch check for simplicity; production should validate AUDIT_ARCH.
		{Code: 0x20, K: 0}, // LD [0] — load nr
	}

	for nr := range allowed {
		// BPF_JMP+BPF_JEQ: if nr == allowed, skip to ALLOW
		skipToAllow := uint8(len(allowed)) // approximate; recalculated below
		prog = append(prog, syscall.SockFilter{
			Code: 0x15,           // JEQ
			Jt:   skipToAllow,
			K:    nr,
		})
	}
	// Default: SECCOMP_RET_ERRNO | EPERM
	prog = append(prog, syscall.SockFilter{
		Code: 0x06, // RET
		K:    0x00050001, // SECCOMP_RET_ERRNO | 1 (EPERM)
	})
	// ALLOW: SECCOMP_RET_ALLOW
	prog = append(prog, syscall.SockFilter{
		Code: 0x06, // RET
		K:    0x7fff0000, // SECCOMP_RET_ALLOW
	})

	// Fix up jump targets: each JEQ should jump to the ALLOW instruction.
	allowIdx := len(prog) - 1
	for i := range prog {
		if prog[i].Code == 0x15 { // JEQ
			prog[i].Jt = uint8(allowIdx - i - 1)
		}
	}
	return prog
}

// syscallNumber maps a name to a syscall number. This is a subset; production
// should use a full table or parse from /usr/include/asm/unistd_64.h.
func syscallNumber(name string) (uint32, bool) {
	// Common syscalls for agent workloads (amd64).
	table := map[string]uint32{
		"read": 0, "write": 1, "open": 2, "close": 3,
		"stat": 4, "fstat": 5, "lstat": 6, "poll": 7,
		"lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11,
		"brk": 12, "ioctl": 16, "access": 21, "pipe": 22,
		"select": 23, "sched_yield": 24, "dup": 32, "dup2": 33,
		"nanosleep": 35, "getpid": 39, "socket": 41, "connect": 42,
		"accept": 43, "sendto": 44, "recvfrom": 45, "bind": 49,
		"listen": 50, "getsockname": 51, "getpeername": 52,
		"clone": 56, "fork": 57, "execve": 59, "exit": 60,
		"wait4": 61, "kill": 62, "uname": 63,
		"fcntl": 72, "flock": 73, "fsync": 74, "fdatasync": 75,
		"getcwd": 79, "chdir": 80, "mkdir": 83, "rmdir": 84,
		"unlink": 87, "readlink": 89, "chmod": 90,
		"getuid": 102, "getgid": 104, "geteuid": 107, "getegid": 108,
		"getppid": 110, "setsid": 112, "rt_sigaction": 13,
		"rt_sigprocmask": 14, "rt_sigreturn": 15,
		"epoll_create1": 291, "epoll_ctl": 233, "epoll_wait": 232,
		"openat": 257, "newfstatat": 262, "futex": 202,
		"clock_gettime": 228, "exit_group": 231,
		"getrandom": 318, "memfd_create": 319,
		"pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20,
		"pipe2": 293, "eventfd2": 290,
	}
	nr, ok := table[name]
	return nr, ok
}

// defaultAgentSyscalls returns a baseline syscall allowlist safe for most
// Python/Node agent workloads. Omits ptrace, mount, reboot, kexec, etc.
func defaultAgentSyscalls() []string {
	return []string{
		"read", "write", "open", "close", "stat", "fstat", "lstat", "poll",
		"lseek", "mmap", "mprotect", "munmap", "brk", "ioctl", "access",
		"pipe", "select", "sched_yield", "dup", "dup2", "nanosleep",
		"getpid", "socket", "connect", "accept", "sendto", "recvfrom",
		"bind", "listen", "getsockname", "getpeername",
		"clone", "fork", "execve", "exit", "wait4", "kill", "uname",
		"fcntl", "flock", "fsync", "fdatasync", "getcwd", "chdir",
		"mkdir", "rmdir", "unlink", "readlink", "chmod",
		"getuid", "getgid", "geteuid", "getegid", "getppid", "setsid",
		"rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
		"epoll_create1", "epoll_ctl", "epoll_wait",
		"openat", "newfstatat", "futex", "clock_gettime", "exit_group",
		"getrandom", "memfd_create", "pread64", "pwrite64", "readv", "writev",
		"pipe2", "eventfd2",
	}
}
