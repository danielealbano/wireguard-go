//go:build android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "testing"

// peekFakeBind is a UDP sub-bind that also exposes PeekLookAtSocketFd (as android's
// StdNetBind does), so a test can assert the multiplex bind forwards the peek.
type peekFakeBind struct {
	fakeUDPBind
	fd4, fd6 int
}

func (p *peekFakeBind) PeekLookAtSocketFd4() (int, error) { return p.fd4, nil }
func (p *peekFakeBind) PeekLookAtSocketFd6() (int, error) { return p.fd6, nil }

// TestMultiplexBind_ForwardsPeek verifies the android multiplex bind forwards
// PeekLookAtSocketFd4/6 to the UDP sub-bind so the embedding app can protect the UDP
// socket.
func TestMultiplexBind_ForwardsPeek(t *testing.T) {
	fake := &peekFakeBind{fd4: 40, fd6: 60}
	ws, err := NewWebSocketBind(WithWSLogger(Logger{}))
	if err != nil {
		t.Fatalf("NewWebSocketBind: %v", err)
	}
	m := &multiplexBind{udp: fake, ws: ws}

	if got, err := m.PeekLookAtSocketFd4(); err != nil || got != 40 {
		t.Errorf("PeekLookAtSocketFd4 = %d, %v; want 40, nil", got, err)
	}
	if got, err := m.PeekLookAtSocketFd6(); err != nil || got != 60 {
		t.Errorf("PeekLookAtSocketFd6 = %d, %v; want 60, nil", got, err)
	}
}
