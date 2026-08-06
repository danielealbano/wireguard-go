//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "fmt"

// The multiplex bind exposes BindSocketToInterface only where the platform UDP
// bind does (windows, WinRingBind), forwarding to it so wireguard-windows can pin
// the underlying UDP socket to an interface.
func (m *multiplexBind) BindSocketToInterface4(interfaceIndex uint32, blackhole bool) error {
	if b, ok := m.udp.(BindSocketToInterface); ok {
		return b.BindSocketToInterface4(interfaceIndex, blackhole)
	}
	return fmt.Errorf("udp bind does not support BindSocketToInterface")
}

func (m *multiplexBind) BindSocketToInterface6(interfaceIndex uint32, blackhole bool) error {
	if b, ok := m.udp.(BindSocketToInterface); ok {
		return b.BindSocketToInterface6(interfaceIndex, blackhole)
	}
	return fmt.Errorf("udp bind does not support BindSocketToInterface")
}
