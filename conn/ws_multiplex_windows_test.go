//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "testing"

// ifaceFakeBind is a UDP sub-bind that also exposes BindSocketToInterface (as windows'
// WinRingBind does), so a test can assert the multiplex bind forwards the call.
type ifaceFakeBind struct {
	fakeUDPBind
	calls         int
	lastIdx       uint32
	lastBlackhole bool
}

func (b *ifaceFakeBind) BindSocketToInterface4(idx uint32, blackhole bool) error {
	b.calls++
	b.lastIdx, b.lastBlackhole = idx, blackhole
	return nil
}

func (b *ifaceFakeBind) BindSocketToInterface6(idx uint32, blackhole bool) error {
	b.calls++
	b.lastIdx, b.lastBlackhole = idx, blackhole
	return nil
}

// TestMultiplexBind_ForwardsBindSocketToInterface verifies the windows multiplex bind
// forwards BindSocketToInterface4/6 to the UDP sub-bind so wireguard-windows can pin the
// UDP socket to an interface.
func TestMultiplexBind_ForwardsBindSocketToInterface(t *testing.T) {
	fake := &ifaceFakeBind{}
	ws, err := NewWebSocketBind(WithWSLogger(Logger{}))
	if err != nil {
		t.Fatalf("NewWebSocketBind: %v", err)
	}
	m := &multiplexBind{udp: fake, ws: ws}

	if err := m.BindSocketToInterface4(7, true); err != nil {
		t.Fatalf("BindSocketToInterface4: %v", err)
	}
	if fake.calls != 1 || fake.lastIdx != 7 || !fake.lastBlackhole {
		t.Errorf("BindSocketToInterface4 not forwarded: calls=%d idx=%d blackhole=%v", fake.calls, fake.lastIdx, fake.lastBlackhole)
	}
	if err := m.BindSocketToInterface6(8, false); err != nil {
		t.Fatalf("BindSocketToInterface6: %v", err)
	}
	if fake.calls != 2 || fake.lastIdx != 8 || fake.lastBlackhole {
		t.Errorf("BindSocketToInterface6 not forwarded: calls=%d idx=%d blackhole=%v", fake.calls, fake.lastIdx, fake.lastBlackhole)
	}
}
