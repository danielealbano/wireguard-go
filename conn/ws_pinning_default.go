//go:build !darwin && !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "syscall"

// dialControl on platforms without an egress-pinning syscall only invokes the
// optional protect callback (a nil Control is valid).
func (b *WebSocketBind) dialControl() func(network, address string, c syscall.RawConn) error {
	if b.cfg.protect == nil {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) { b.cfg.protect(int(fd)) })
	}
}
