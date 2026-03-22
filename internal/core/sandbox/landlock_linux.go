//go:build linux

package sandbox

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	// Landlock syscall numbers (amd64).
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446

	// Access flags for filesystem (Landlock ABI v1+).
	accessFSExecute    = 1 << 0
	accessFSWriteFile  = 1 << 1
	accessFSReadFile   = 1 << 2
	accessFSReadDir    = 1 << 3
	accessFSRemoveDir  = 1 << 4
	accessFSRemoveFile = 1 << 5
	accessFSMakeChar   = 1 << 6
	accessFSMakeDir    = 1 << 7
	accessFSMakeReg    = 1 << 8
	accessFSMakeSock   = 1 << 9
	accessFSMakeFifo   = 1 << 10
	accessFSMakeBlock  = 1 << 11
	accessFSMakeSym    = 1 << 12
	accessFSRefer      = 1 << 13 // ABI v2
	accessFSTruncate   = 1 << 14 // ABI v3

	landlockRulePathBeneath = 1
)

// LandlockRule describes a filesystem access rule.
type LandlockRule struct {
	Path     string
	Readable bool
	Writable bool
	Exec     bool
}

type landlockRulesetAttr struct {
	handledAccessFS uint64
}

type landlockPathBeneathAttr struct {
	allowedAccess uint64
	parentFd      int32
}

// ApplyLandlockRules installs Landlock LSM restrictions for the current process.
// Once applied, the process (and children) cannot access paths outside the rules.
// Requires Linux 5.13+ with Landlock enabled.
func ApplyLandlockRules(rules []LandlockRule) error {
	handled := uint64(accessFSReadFile | accessFSReadDir |
		accessFSWriteFile | accessFSRemoveDir | accessFSRemoveFile |
		accessFSMakeDir | accessFSMakeReg | accessFSMakeSym |
		accessFSExecute)

	attr := landlockRulesetAttr{handledAccessFS: handled}

	rulesetFd, _, errno := syscall.RawSyscall(
		uintptr(sysLandlockCreateRuleset),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %v (kernel may not support Landlock)", errno)
	}
	defer syscall.Close(int(rulesetFd))

	for _, rule := range rules {
		fd, err := syscall.Open(rule.Path, syscall.O_PATH|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open path %q for Landlock: %w", rule.Path, err)
		}

		var access uint64
		if rule.Readable {
			access |= accessFSReadFile | accessFSReadDir
		}
		if rule.Writable {
			access |= accessFSWriteFile | accessFSRemoveDir | accessFSRemoveFile |
				accessFSMakeDir | accessFSMakeReg | accessFSMakeSym
		}
		if rule.Exec {
			access |= accessFSExecute
		}
		if access == 0 {
			access = accessFSReadFile | accessFSReadDir
		}

		pathAttr := landlockPathBeneathAttr{
			allowedAccess: access,
			parentFd:      int32(fd),
		}

		_, _, errno := syscall.RawSyscall6(
			uintptr(sysLandlockAddRule),
			rulesetFd,
			uintptr(landlockRulePathBeneath),
			uintptr(unsafe.Pointer(&pathAttr)),
			unsafe.Sizeof(pathAttr),
			0, 0,
		)
		syscall.Close(fd)
		if errno != 0 {
			return fmt.Errorf("landlock_add_rule(%s): %v", rule.Path, errno)
		}
	}

	// PR_SET_NO_NEW_PRIVS is required.
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, 38, 1, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %v", errno)
	}

	if _, _, errno := syscall.RawSyscall(
		uintptr(sysLandlockRestrictSelf),
		rulesetFd, 0, 0,
	); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %v", errno)
	}
	return nil
}

// PolicyToLandlockRules converts a SandboxConfig into Landlock rules.
// The agent gets read access to /usr, /lib, /etc (runtime), plus
// read+write to declared workspace paths.
func PolicyToLandlockRules(cfg *SandboxConfig, workspacePaths []string) []LandlockRule {
	rules := []LandlockRule{
		{Path: "/usr", Readable: true, Exec: true},
		{Path: "/lib", Readable: true, Exec: true},
		{Path: "/lib64", Readable: true, Exec: true},
		{Path: "/etc", Readable: true},
		{Path: "/tmp", Readable: true, Writable: true},
		{Path: "/dev/null", Readable: true, Writable: true},
		{Path: "/dev/urandom", Readable: true},
		{Path: "/proc", Readable: true},
	}
	for _, ws := range workspacePaths {
		if ws == "" {
			continue
		}
		rules = append(rules, LandlockRule{
			Path:     ws,
			Readable: true,
			Writable: !cfg.ReadOnlyRoot,
		})
	}
	return rules
}
