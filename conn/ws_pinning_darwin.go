//go:build darwin

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "syscall"

// dialControl on darwin only invokes the optional protect callback. Keeping the
// WebSocket transport off the tun under a full-tunnel is wg-quick's job: it
// host-routes the endpoint ip:port via the physical gateway
// (set_endpoint_direct_route), exactly as it does for UDP — and endpoint= is now a
// routable ip:port. wireguard-go adds no routing/pinning here; an IP_BOUND_IF pin
// would be harmful under full-tunnel (the default route can be the utun, and
// IP_BOUND_IF overrides the routing table).
func (b *WebSocketBind) dialControl() func(network, address string, c syscall.RawConn) error {
	if b.cfg.protect == nil {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) { b.cfg.protect(int(fd)) })
	}
}
