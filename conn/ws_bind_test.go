/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

func newClientBind(t *testing.T) *conn.WebSocketBind {
	t.Helper()
	b, err := conn.NewWebSocketBind(conn.WithWSLogger(conn.Logger{}))
	if err != nil {
		t.Fatalf("NewWebSocketBind: %v", err)
	}
	return b
}

func TestWSEndpoint_ParseEndpoint_IPPort(t *testing.T) {
	b := newClientBind(t)
	for _, s := range []string{"1.2.3.4:80", "[::1]:443", "10.0.0.9:8443"} {
		ep, err := b.ParseEndpoint(s)
		if err != nil {
			t.Fatalf("ParseEndpoint(%q): %v", s, err)
		}
		if ep.DstToString() != s {
			t.Errorf("round trip %q -> %q", s, ep.DstToString())
		}
		_ = ep.DstIP()
		_ = ep.DstToBytes()
	}
	if _, err := b.ParseEndpoint("wss://not-an-ip-port"); err == nil {
		t.Error("ParseEndpoint should reject a non ip:port")
	}
}

func TestWebSocketBind_ParseWSPeerEndpoint(t *testing.T) {
	b := newClientBind(t)
	ep := netip.MustParseAddrPort
	tests := []struct {
		name    string
		cfg     conn.WSPeerConfig
		wantErr bool
	}{
		{name: "websocket", cfg: conn.WSPeerConfig{Endpoint: ep("10.0.0.1:443"), Transport: "websocket", URL: "wss://h/p"}},
		{name: "wstunnel with target", cfg: conn.WSPeerConfig{Endpoint: ep("10.0.0.1:443"), Transport: "wstunnel", URL: "wss://h/p", WstunnelTarget: "1.2.3.4:51820"}},
		{name: "wstunnel without target", cfg: conn.WSPeerConfig{Endpoint: ep("10.0.0.1:443"), Transport: "wstunnel", URL: "wss://h/p"}, wantErr: true},
		{name: "wstunnel_target on websocket", cfg: conn.WSPeerConfig{Endpoint: ep("10.0.0.1:443"), Transport: "websocket", URL: "wss://h/p", WstunnelTarget: "1.2.3.4:51820"}, wantErr: true},
		{name: "bad scheme", cfg: conn.WSPeerConfig{Endpoint: ep("10.0.0.1:443"), Transport: "websocket", URL: "http://h/p"}, wantErr: true},
		{name: "bad transport", cfg: conn.WSPeerConfig{Endpoint: ep("10.0.0.1:443"), Transport: "bogus", URL: "wss://h/p"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := b.ParseWSPeerEndpoint(tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestWebSocketBind_SetMark(t *testing.T) {
	b := newClientBind(t)
	// No open connections: SetMark stores the mark and is a no-op re-mark (never fails).
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
		conn.WithWSProtect(func(fd int) { mu.Lock(); called++; mu.Unlock() }),
	)
	if err != nil {
		t.Fatalf("bind with protect: %v", err)
	}
	_ = called
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
	if err := b.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
