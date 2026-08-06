/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

func newMultiplex(t *testing.T) conn.Bind {
	t.Helper()
	b, err := conn.NewMultiplexBind(conn.WithWSLogger(conn.Logger{}))
	if err != nil {
		t.Fatalf("NewMultiplexBind: %v", err)
	}
	return b
}

func TestMultiplexBind_ImplementsInterfaces(t *testing.T) {
	b := newMultiplex(t)
	if _, ok := b.(conn.WebSocketBinder); !ok {
		t.Error("multiplex bind must implement conn.WebSocketBinder")
	}
	if _, ok := b.(conn.WebSocketMetricsProvider); !ok {
		t.Error("multiplex bind must implement conn.WebSocketMetricsProvider")
	}
	if _, ok := b.(interface{ WSInUse() bool }); !ok {
		t.Error("multiplex bind must expose WSInUse")
	}
}

func TestMultiplexBind_OpenUnionReceiveFuncs(t *testing.T) {
	b := newMultiplex(t)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	// At least one UDP receive func plus the WebSocket receive func.
	if len(fns) < 2 {
		t.Errorf("Open returned %d receive funcs, want >= 2 (UDP + WS)", len(fns))
	}
}

func TestMultiplexBind_ParseEndpointIsUDP(t *testing.T) {
	b := newMultiplex(t)
	ep, err := b.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if _, ok := ep.(*conn.WSEndpoint); ok {
		t.Error("a plain ip:port endpoint must be a UDP endpoint, not *WSEndpoint")
	}
}

func TestMultiplexBind_WSInUseGate(t *testing.T) {
	b := newMultiplex(t)
	wb := b.(interface{ WSInUse() bool })
	if wb.WSInUse() {
		t.Error("fresh bind should report WSInUse=false")
	}
	if err := b.(conn.WebSocketBinder).SetWSListen("ws://127.0.0.1:1/wg"); err != nil {
		t.Fatalf("SetWSListen: %v", err)
	}
	if !wb.WSInUse() {
		t.Error("ws_listen set => WSInUse should be true")
	}
}

func TestMultiplexBind_SetMarkNoConnsIsNil(t *testing.T) {
	b := newMultiplex(t)
	// Before Open the UDP sockets are nil and there are no WS conns, so SetMark is a
	// no-op on both sub-binds (privilege-free).
	if err := b.SetMark(0x55); err != nil {
		t.Errorf("SetMark on an unopened multiplex bind: %v", err)
	}
}
