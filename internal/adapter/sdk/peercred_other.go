//go:build !linux

package sdk

import "net"

import "go.uber.org/zap"

func logPeerCredentials(_ *zap.Logger, _ net.Conn) {}
