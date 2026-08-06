//go:build android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "fmt"

// The multiplex bind exposes PeekLookAtSocketFd only where the platform UDP bind
// does (android, StdNetBind), forwarding to it so the embedding app can protect
// the underlying UDP socket.
func (m *multiplexBind) PeekLookAtSocketFd4() (int, error) {
	if p, ok := m.udp.(PeekLookAtSocketFd); ok {
		return p.PeekLookAtSocketFd4()
	}
	return -1, fmt.Errorf("udp bind does not support PeekLookAtSocketFd")
}

func (m *multiplexBind) PeekLookAtSocketFd6() (int, error) {
	if p, ok := m.udp.(PeekLookAtSocketFd); ok {
		return p.PeekLookAtSocketFd6()
	}
	return -1, fmt.Errorf("udp bind does not support PeekLookAtSocketFd")
}
