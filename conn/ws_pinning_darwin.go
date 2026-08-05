//go:build darwin

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// dialControl binds each dialed socket to the physical egress interface via
// IP_BOUND_IF / IPV6_BOUND_IF, and invokes the optional protect callback, so the
// WebSocket transport does not loop back into the tun. Recomputed on every dial.
func (b *WebSocketBind) dialControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		idx := b.egressIfIndex() // recomputed per dial; 0 => skip pin
		v6 := wsIsIPv6(address)
		var serr error
		cerr := c.Control(func(fd uintptr) {
			if idx > 0 {
				if v6 {
					serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx)
				} else {
					serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
				}
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
