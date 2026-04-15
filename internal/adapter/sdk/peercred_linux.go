//go:build linux

package sdk

import (
	"net"
	"syscall"

	"go.uber.org/zap"
)

func logPeerCredentials(log *zap.Logger, conn net.Conn) {
	if log == nil || conn == nil {
		return
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		log.Warn("sdk peer credential lookup failed", zap.Error(err))
		return
	}

	var cred *syscall.Ucred
	var controlErr error
	if err := rawConn.Control(func(fd uintptr) {
		cred, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		log.Warn("sdk peer credential lookup failed", zap.Error(err))
		return
	}
	if controlErr != nil {
		log.Warn("sdk peer credential lookup failed", zap.Error(controlErr))
		return
	}
	if cred == nil {
		return
	}

	log.Info("sdk peer credentials verified",
		zap.Int("peer_uid", int(cred.Uid)),
		zap.Int("peer_gid", int(cred.Gid)),
		zap.Int("peer_pid", int(cred.Pid)))
}
