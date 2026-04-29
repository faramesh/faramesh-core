//go:build linux

package proxy

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func resolveProcessIdentity(r *http.Request) (*ProcessIdentity, error) {
	if r == nil {
		return nil, fmt.Errorf("request is nil")
	}

	_, peerPort, err := splitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("parse remote addr: %w", err)
	}

	localAny := r.Context().Value(http.LocalAddrContextKey)
	localAddr, ok := localAny.(net.Addr)
	if !ok || localAddr == nil {
		return nil, fmt.Errorf("missing local listener address")
	}
	_, listenerPort, err := splitHostPort(localAddr.String())
	if err != nil {
		return nil, fmt.Errorf("parse local listener addr: %w", err)
	}

	inode, err := findSocketInode(peerPort, listenerPort)
	if err != nil {
		return nil, err
	}
	pid, err := findPIDForInode(inode)
	if err != nil {
		return nil, err
	}

	exePath, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return nil, fmt.Errorf("read process executable path: %w", err)
	}

	digest, err := fileSHA256(exePath)
	if err != nil {
		return nil, fmt.Errorf("hash executable: %w", err)
	}

	return &ProcessIdentity{
		PID:              pid,
		Executable:       exePath,
		ExecutableSHA256: digest,
	}, nil
}

func splitHostPort(addr string) (string, int, error) {
	host, portRaw, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(strings.TrimSpace(portRaw))
	if err != nil {
		return "", 0, err
	}
	return strings.Trim(host, "[]"), port, nil
}

func findSocketInode(peerPort, listenerPort int) (string, error) {
	for _, tablePath := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		inode, err := findSocketInodeInTable(tablePath, peerPort, listenerPort)
		if err != nil {
			continue
		}
		if inode != "" {
			return inode, nil
		}
	}
	return "", fmt.Errorf("socket inode not found for peer_port=%d listener_port=%d", peerPort, listenerPort)
}

func findSocketInodeInTable(path string, peerPort, listenerPort int) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("unexpected %s format", path)
	}

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		localPort, errLocal := parseProcNetPort(fields[1])
		remotePort, errRemote := parseProcNetPort(fields[2])
		if errLocal != nil || errRemote != nil {
			continue
		}
		if localPort != listenerPort || remotePort != peerPort {
			continue
		}
		state := fields[3]
		if state != "01" && state != "06" {
			continue
		}
		inode := fields[9]
		if strings.TrimSpace(inode) != "" {
			return strings.TrimSpace(inode), nil
		}
	}

	return "", nil
}

func parseProcNetPort(addrPort string) (int, error) {
	parts := strings.Split(addrPort, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid addr:port format: %s", addrPort)
	}
	portHex := strings.TrimSpace(parts[1])
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return 0, err
	}
	return int(port), nil
}

func findPIDForInode(inode string) (int, error) {
	target := "socket:[" + strings.TrimSpace(inode) + "]"
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			linkPath := filepath.Join(fdDir, fd.Name())
			link, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}
			if link == target {
				return pid, nil
			}
		}
	}

	return 0, fmt.Errorf("pid not found for socket inode %s", inode)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
