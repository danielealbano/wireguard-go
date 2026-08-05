/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"errors"
	"net"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

func newClientBind(t *testing.T) *conn.WebSocketBind {
	t.Helper()
	b, err := conn.NewWebSocketBind(conn.WithWSRole(conn.WSRoleClient))
	if err != nil {
		t.Fatalf("NewWebSocketBind: %v", err)
	}
	return b
}

func TestWSEndpoint_RoundTrip(t *testing.T) {
	b := newClientBind(t)
	for _, u := range []string{"ws://host:80/path", "wss://host:443/a/b", "wss://[::1]:443/"} {
		ep, err := b.ParseEndpoint(u)
		if err != nil {
			t.Fatalf("ParseEndpoint(%q): %v", u, err)
		}
		if ep.DstToString() != u {
			t.Errorf("round trip %q -> %q", u, ep.DstToString())
		}
		// DstIP/DstToBytes must not panic on a zero dst.
		_ = ep.DstIP()
		_ = ep.DstToBytes()
	}
}

func TestWebSocketBind_ParseWSPeerEndpoint(t *testing.T) {
	b := newClientBind(t)
	tests := []struct {
		name    string
		url     string
		mode    string
		target  string
		wantErr bool
	}{
		{name: "standard", url: "wss://h/p", mode: "standard", wantErr: false},
		{name: "wstunnel with target", url: "wss://h/p", mode: "wstunnel", target: "1.2.3.4:51820", wantErr: false},
		{name: "wstunnel without target", url: "wss://h/p", mode: "wstunnel", target: "", wantErr: true},
		{name: "bad scheme", url: "http://h/p", mode: "standard", wantErr: true},
		{name: "bad mode", url: "wss://h/p", mode: "bogus", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := b.ParseWSPeerEndpoint(tc.url, tc.mode, tc.target, "")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestNewBindForTransport(t *testing.T) {
	udp, err := conn.NewBindForTransport("")
	if err != nil || udp == nil {
		t.Fatalf("udp default: %v", err)
	}
	if _, ok := udp.(*conn.WebSocketBind); ok {
		t.Error("empty transport should not be a WebSocketBind")
	}
	ws, err := conn.NewBindForTransport("ws", conn.WithWSRole(conn.WSRoleClient))
	if err != nil {
		t.Fatalf("ws: %v", err)
	}
	if _, ok := ws.(*conn.WebSocketBind); !ok {
		t.Errorf("ws transport = %T, want *WebSocketBind", ws)
	}
	if _, err := conn.NewBindForTransport("bogus"); err == nil {
		t.Error("expected error for invalid transport")
	}
}

func TestWebSocketBind_SetMark(t *testing.T) {
	b := newClientBind(t)
	if err := b.SetMark(0x1234); err != nil {
		t.Fatalf("SetMark: %v", err)
	}
}

func TestWSBind_NotPeekLookAtSocketFd(t *testing.T) {
	b := newClientBind(t)
	if _, ok := any(b).(conn.PeekLookAtSocketFd); ok {
		t.Error("WebSocketBind must NOT implement conn.PeekLookAtSocketFd")
	}
}

func TestWSBind_ProtectOption(t *testing.T) {
	var called int
	var mu sync.Mutex
	_, err := conn.NewWebSocketBind(
		conn.WithWSRole(conn.WSRoleClient),
		conn.WithWSProtect(func(fd int) { mu.Lock(); called++; mu.Unlock() }),
	)
	if err != nil {
		t.Fatalf("bind with protect: %v", err)
	}
	// The callback is exercised per dial in the pinning tests / on-device; here we
	// only assert the option is accepted.
}

func TestWSClient_CloseUnblocksReceive(t *testing.T) {
	b := newClientBind(t)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	errc := make(chan error, len(fns))
	for _, fn := range fns {
		go func(fn conn.ReceiveFunc) {
			bufs := [][]byte{make([]byte, 2048)}
			_, err := fn(bufs, make([]int, 1), make([]conn.Endpoint, 1))
			errc <- err
		}(fn)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for range fns {
		if err := <-errc; !errors.Is(err, net.ErrClosed) {
			t.Errorf("receive after close = %v, want net.ErrClosed", err)
		}
	}
	// Close is idempotent.
	if err := b.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
