/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net/netip"
	"testing"
	"time"
)

// TestWSEndpoint_DstToString_ClientResolved: a dialing endpoint reports its resolved
// dial target (a routable ip:port, like UDP), a server (inbound) endpoint reports
// the client address.
func TestWSEndpoint_DstToString_ClientResolved(t *testing.T) {
	client := &WSEndpoint{wsURL: "wss://relay.example.com:8443/wg", dialTarget: netip.MustParseAddrPort("10.0.0.9:8443")}
	if got := client.DstToString(); got != "10.0.0.9:8443" {
		t.Errorf("client DstToString = %q, want 10.0.0.9:8443", got)
	}
	server := &WSEndpoint{dst: netip.MustParseAddrPort("203.0.113.5:5000")}
	if got := server.DstToString(); got != "203.0.113.5:5000" {
		t.Errorf("server DstToString = %q, want 203.0.113.5:5000", got)
	}
}

// TestWSEndpoint_KeyDistinguishesPeers: endpoints sharing a ws_url but differing in
// dial target or wstunnel target produce different connection keys (no collision).
func TestWSEndpoint_KeyDistinguishesPeers(t *testing.T) {
	mk := func(target, wst string) *WSEndpoint {
		return &WSEndpoint{wsURL: "wss://relay:8443", dialTarget: netip.MustParseAddrPort(target), wstunnelTarget: wst}
	}
	a := mk("10.0.0.1:8443", "192.168.1.1:51820")
	b := mk("10.0.0.2:8443", "192.168.1.1:51820")
	c := mk("10.0.0.1:8443", "192.168.1.2:51820")
	if a.key() == b.key() || a.key() == c.key() || b.key() == c.key() {
		t.Errorf("keys collided: %q / %q / %q", a.key(), b.key(), c.key())
	}
}

// TestWSEndpoint_WSPeerKVs: a dialing endpoint round-trips its configured per-peer
// keys (omitting empties); an inbound endpoint emits none.
func TestWSEndpoint_WSPeerKVs(t *testing.T) {
	e := &WSEndpoint{
		wsURL: "wss://relay:8443/wg", dialTarget: netip.MustParseAddrPort("10.0.0.9:8443"),
		dialect: wsDialectWstunnel, wstunnelTarget: "192.168.1.1:51820", bearer: "tok",
		mask: true, tlsInsecure: true,
	}
	got := map[string]bool{}
	for _, kv := range e.WSPeerKVs() {
		got[kv] = true
	}
	for _, want := range []string{
		"ws_url=wss://relay:8443/wg", "wstunnel_target=192.168.1.1:51820",
		"ws_bearer=tok", "ws_mask=true", "ws_tls_insecure=true",
	} {
		if !got[want] {
			t.Errorf("missing kv %q in %v", want, got)
		}
	}
	if len((&WSEndpoint{dst: netip.MustParseAddrPort("1.2.3.4:5")}).WSPeerKVs()) != 0 {
		t.Error("inbound endpoint should emit no ws_* keys")
	}
}

// TestParseWSPeerEndpoint_TimingDefaults verifies the per-peer timings normalize to the
// package defaults when the ws_ping_interval / ws_backoff_* keys are absent (so pingLoop
// keeps pinging and backoff is non-zero) and are honored when set. It also checks the
// plain ParseEndpoint(ip:port) path applies the same defaults.
func TestParseWSPeerEndpoint_TimingDefaults(t *testing.T) {
	b, err := NewWebSocketBind(WithWSLogger(Logger{}))
	if err != nil {
		t.Fatalf("NewWebSocketBind: %v", err)
	}
	base := WSPeerConfig{Endpoint: netip.MustParseAddrPort("10.0.0.1:443"), Transport: "websocket", URL: "wss://h/p"}

	epDef, err := b.ParseWSPeerEndpoint(base)
	if err != nil {
		t.Fatalf("ParseWSPeerEndpoint(defaults): %v", err)
	}
	we := epDef.(*WSEndpoint)
	if we.pingInterval != wsDefaultPingInterval || we.backoffMin != wsDefaultBackoffMin || we.backoffMax != wsDefaultBackoffMax {
		t.Errorf("defaults not applied: ping=%v min=%v max=%v", we.pingInterval, we.backoffMin, we.backoffMax)
	}

	set := base
	set.PingInterval, set.BackoffMin, set.BackoffMax = 7*time.Second, 100*time.Millisecond, 9*time.Second
	epSet, err := b.ParseWSPeerEndpoint(set)
	if err != nil {
		t.Fatalf("ParseWSPeerEndpoint(set): %v", err)
	}
	we = epSet.(*WSEndpoint)
	if we.pingInterval != 7*time.Second || we.backoffMin != 100*time.Millisecond || we.backoffMax != 9*time.Second {
		t.Errorf("explicit timings not honored: ping=%v min=%v max=%v", we.pingInterval, we.backoffMin, we.backoffMax)
	}

	epPlain, err := b.ParseEndpoint("10.0.0.1:443")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	we = epPlain.(*WSEndpoint)
	if we.pingInterval != wsDefaultPingInterval || we.backoffMin != wsDefaultBackoffMin || we.backoffMax != wsDefaultBackoffMax {
		t.Errorf("ParseEndpoint defaults not applied: ping=%v min=%v max=%v", we.pingInterval, we.backoffMin, we.backoffMax)
	}
}
