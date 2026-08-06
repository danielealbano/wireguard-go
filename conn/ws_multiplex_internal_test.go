/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// fakeUDPBind is a recording conn.Bind stand-in for the platform UDP sub-bind, so a
// test can assert exactly which sub-bind the multiplex bind dispatched to.
type fakeUDPBind struct {
	sendCount    int
	setMarkCount int
	lastMark     uint32
	closeCount   int
}

func (f *fakeUDPBind) Open(uint16) ([]ReceiveFunc, uint16, error) { return nil, 0, nil }
func (f *fakeUDPBind) Close() error                               { f.closeCount++; return nil }
func (f *fakeUDPBind) SetMark(m uint32) error                     { f.setMarkCount++; f.lastMark = m; return nil }
func (f *fakeUDPBind) Send([][]byte, Endpoint) error              { f.sendCount++; return nil }
func (f *fakeUDPBind) ParseEndpoint(string) (Endpoint, error)     { return fakeEndpoint{}, nil }
func (f *fakeUDPBind) BatchSize() int                             { return 1 }

// fakeEndpoint is a non-*WSEndpoint endpoint, so multiplex dispatch routes it to UDP.
type fakeEndpoint struct{}

func (fakeEndpoint) ClearSrc()           {}
func (fakeEndpoint) SrcToString() string { return "" }
func (fakeEndpoint) DstToString() string { return "fake" }
func (fakeEndpoint) DstToBytes() []byte  { return nil }
func (fakeEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (fakeEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// TestMultiplexBind_Send_DispatchByType verifies Send routes a *WSEndpoint to the
// WebSocket sub-bind and any other endpoint to the UDP sub-bind — the core guarantee
// that mixed (UDP + WebSocket) peers on one device never cross wires.
func TestMultiplexBind_Send_DispatchByType(t *testing.T) {
	fake := &fakeUDPBind{}
	ws, err := NewWebSocketBind(WithWSLogger(Logger{}))
	if err != nil {
		t.Fatalf("NewWebSocketBind: %v", err)
	}
	m := &multiplexBind{udp: fake, ws: ws}

	if err := m.Send([][]byte{{1}}, fakeEndpoint{}); err != nil {
		t.Fatalf("udp send: %v", err)
	}
	if fake.sendCount != 1 {
		t.Fatalf("non-WS endpoint: udp sendCount = %d, want 1", fake.sendCount)
	}

	// A *WSEndpoint must go to the WS sub-bind (server-kind → serverSend error), never UDP.
	_ = m.Send([][]byte{{2}}, &WSEndpoint{connID: 3})
	if fake.sendCount != 1 {
		t.Errorf("a *WSEndpoint was routed to the UDP sub-bind (sendCount = %d)", fake.sendCount)
	}
}

// TestMultiplexBind_SetMarkCloseFanout verifies SetMark and Close reach BOTH sub-binds
// (the fwmark must be applied to the UDP socket and every WS socket).
func TestMultiplexBind_SetMarkCloseFanout(t *testing.T) {
	fake := &fakeUDPBind{}
	ws, err := NewWebSocketBind(WithWSLogger(Logger{}))
	if err != nil {
		t.Fatalf("NewWebSocketBind: %v", err)
	}
	m := &multiplexBind{udp: fake, ws: ws}

	if err := m.SetMark(0x99); err != nil {
		t.Fatalf("SetMark: %v", err)
	}
	if fake.setMarkCount != 1 || fake.lastMark != 0x99 {
		t.Errorf("UDP SetMark not forwarded: count=%d mark=%#x", fake.setMarkCount, fake.lastMark)
	}
	if ws.mark.Load() != 0x99 {
		t.Errorf("WS SetMark not forwarded: mark=%#x, want 0x99", ws.mark.Load())
	}

	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if fake.closeCount != 1 {
		t.Errorf("UDP Close not forwarded: count=%d, want 1", fake.closeCount)
	}
}

// TestWSBind_Send_DispatchByEndpointKind verifies the WebSocket bind's own Send dispatch:
// an accepted (server-kind) endpoint carrying a connID replies over that connection, and a
// non-*WSEndpoint is rejected. The dialing (client-kind) branch is covered by the tunnel
// tests, which drive real dials.
func TestWSBind_Send_DispatchByEndpointKind(t *testing.T) {
	b, err := NewWebSocketBind(WithWSLogger(Logger{}))
	if err != nil {
		t.Fatalf("NewWebSocketBind: %v", err)
	}

	// Server-kind endpoint: no ws_url, a connID with no live connection => id-specific error.
	err = b.Send([][]byte{{1}}, &WSEndpoint{connID: 9})
	if err == nil || !strings.Contains(err.Error(), "id 9") {
		t.Errorf("server-kind Send err = %v, want a 'no active connection ... id 9' error", err)
	}

	// Wrong endpoint type => ErrWrongEndpointType.
	if err := b.Send([][]byte{{1}}, fakeEndpoint{}); !errors.Is(err, ErrWrongEndpointType) {
		t.Errorf("wrong-type Send err = %v, want ErrWrongEndpointType", err)
	}
}
