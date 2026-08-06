//go:build !linux && !freebsd && !openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "net"

// markConn is a no-op on darwin/windows: their UDP transport also no-ops SetMark
// (mark_default.go), and the WebSocket transport stays off-tun via other means
// (darwin: wg-quick host-routes endpoint=ip:port; windows: interface binding).
func markConn(_ net.Conn, _ uint32) error { return nil }
