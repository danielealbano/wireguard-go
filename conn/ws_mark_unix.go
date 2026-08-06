//go:build linux || freebsd || openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// markRawFd sets the per-OS fwmark socket option (fwmarkIoctl: SO_MARK on
// linux/android, SO_USER_COOKIE on freebsd, SO_RTABLE on openbsd) on fd. It is a
// no-op when no fwmark is configured (mark==0): the kernel requires
// CAP_NET_RAW/CAP_NET_ADMIN to set SO_MARK to ANY value, including 0, so an
// unprivileged dialer that never sets a fwmark (e.g. Android, which pins egress
// with VpnService.protect instead) must not touch SO_MARK — otherwise the setsockopt
// returns EPERM, failing the dial and skipping the protect callback.
func markRawFd(fd uintptr, mark uint32) error {
	if fwmarkIoctl == 0 || mark == 0 {
		return nil
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
}

// markConn applies the fwmark to c's underlying socket, unwrapping *tls.Conn to
// the net.Conn that implements syscall.Conn.
func markConn(c net.Conn, mark uint32) error {
	rc, err := rawConnOf(c)
	if err != nil {
		return err
	}
	var operr error
	if err := rc.Control(func(fd uintptr) { operr = markRawFd(fd, mark) }); err != nil {
		return err
	}
	return operr
}

// rawConnOf reaches the syscall.RawConn behind a net.Conn, unwrapping *tls.Conn
// (which exposes NetConn()) down to the *net.TCPConn that implements syscall.Conn.
// Co-located with its sole caller markConn (unused on darwin/windows otherwise).
func rawConnOf(c net.Conn) (syscall.RawConn, error) {
	for {
		switch v := c.(type) {
		case syscall.Conn:
			return v.SyscallConn()
		case interface{ NetConn() net.Conn }:
			c = v.NetConn()
		default:
			return nil, fmt.Errorf("connection type %T exposes no raw fd", c)
		}
	}
}
