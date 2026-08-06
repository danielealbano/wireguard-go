//go:build linux || freebsd || openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"syscall"
)

// dialControl marks each dialed socket with the per-OS fwmark (fwmarkIoctl:
// SO_MARK on linux/android, SO_USER_COOKIE on freebsd, SO_RTABLE on openbsd) so
// policy routing keeps the WebSocket transport off the tun, and invokes the
// optional protect callback. Also compiled for GOOS=android (satisfies the linux
// build constraint); there SO_MARK is unprivileged-safe and the protect callback
// delivers VpnService.protect. Recomputed on every dial.
func (b *WebSocketBind) dialControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		mark := b.mark.Load()
		var serr error
		cerr := c.Control(func(fd uintptr) {
			serr = markRawFd(fd, mark)
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
