//go:build linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// dialControl marks each dialed socket with SO_MARK (policy routing keeps the
// WebSocket transport off the tun) and invokes the optional protect callback.
// Also compiled for GOOS=android, which satisfies the linux build constraint;
// there SO_MARK is unprivileged-safe and the protect callback delivers
// VpnService.protect. Recomputed on every dial.
func (b *WebSocketBind) dialControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		mark := b.mark.Load()
		var serr error
		cerr := c.Control(func(fd uintptr) {
			if mark != 0 {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			}
			if serr == nil && b.cfg.protect != nil {
				b.cfg.protect(int(fd))
			}
		})
		if cerr != nil {
			return cerr
		}
		return serr
	}
}
