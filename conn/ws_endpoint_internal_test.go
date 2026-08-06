/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net/netip"
	"testing"
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
