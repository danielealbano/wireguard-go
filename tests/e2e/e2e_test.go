//go:build linux && e2e

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package e2e

import (
	"fmt"
	"testing"
)

// Underlay subnet 10.9.0.0/24 (bridge); tunnel subnet 10.10.0.0/24.
// Client = 10.9.0.1 / tunnel 10.10.0.1; server = 10.9.0.2 / tunnel 10.10.0.2;
// wstunnel = 10.9.0.3. The daemon interface names are assigned by startDaemon.
// All tunnel config arrives via the UAPI now — the daemon needs no WS environment.

func TestE2E_UDP(t *testing.T) {
	l := newLab(t)
	br := l.addBridge()
	nsC := l.addNS()
	nsS := l.addNS()
	l.vethToBridge(nsC, br, "10.9.0.1/24")
	l.vethToBridge(nsS, br, "10.9.0.2/24")

	privC, pubC := genKeypair(t)
	privS, pubS := genKeypair(t)

	wgS := l.startDaemon(nsS, nil)
	l.uapiSet(wgS, fmt.Sprintf("private_key=%s\nlisten_port=51820\npublic_key=%s\ntransport=udp\nallowed_ip=10.10.0.1/32\n", privS, pubC))
	l.ifup(nsS, wgS, "10.10.0.2/24")

	wgC := l.startDaemon(nsC, nil)
	l.uapiSet(wgC, fmt.Sprintf("private_key=%s\npublic_key=%s\ntransport=udp\nendpoint=10.9.0.2:51820\nallowed_ip=10.10.0.2/32\npersistent_keepalive_interval=1\n", privC, pubS))
	l.ifup(nsC, wgC, "10.10.0.1/24")

	if !l.ping(nsC, "10.10.0.2") {
		t.Fatal("ping through the UDP tunnel failed")
	}
}

func TestE2E_WebSocket(t *testing.T) {
	l := newLab(t)
	br := l.addBridge()
	nsC := l.addNS()
	nsS := l.addNS()
	l.vethToBridge(nsC, br, "10.9.0.1/24")
	l.vethToBridge(nsS, br, "10.9.0.2/24")

	privC, pubC := genKeypair(t)
	privS, pubS := genKeypair(t)
	cert, key := genServerCert(t, "10.9.0.2")
	wsURL := "wss://10.9.0.2:51820/wg"

	wgS := l.startDaemon(nsS, nil)
	l.uapiSet(wgS, fmt.Sprintf("private_key=%s\nws_listen=%s\nws_server_tls_cert=%s\nws_server_tls_key=%s\npublic_key=%s\ntransport=websocket\nallowed_ip=10.10.0.1/32\n", privS, wsURL, cert, key, pubC))
	l.ifup(nsS, wgS, "10.10.0.2/24")

	wgC := l.startDaemon(nsC, nil)
	l.uapiSet(wgC, fmt.Sprintf("private_key=%s\npublic_key=%s\ntransport=websocket\nendpoint=10.9.0.2:51820\nws_url=%s\nws_tls_ca=%s\nallowed_ip=10.10.0.2/32\npersistent_keepalive_interval=1\n", privC, pubS, wsURL, cert))
	l.ifup(nsC, wgC, "10.10.0.1/24")

	if !l.ping(nsC, "10.10.0.2") {
		t.Fatal("ping through the WebSocket tunnel failed")
	}
}

// TestE2E_WebSocket_FullTunnel reproduces the reported bug: under wg-quick's Linux
// full-tunnel mechanism (fwmark + `ip rule not fwmark`), the WebSocket transport
// socket must carry the mark or it self-loops into the tun. The mark is set AFTER
// the connection is established, so this exercises the live re-mark specifically.
func TestE2E_WebSocket_FullTunnel(t *testing.T) {
	l := newLab(t)
	br := l.addBridge()
	nsC := l.addNS()
	nsS := l.addNS()
	l.vethToBridge(nsC, br, "10.9.0.1/24")
	l.vethToBridge(nsS, br, "10.9.0.2/24")

	privC, pubC := genKeypair(t)
	privS, pubS := genKeypair(t)
	cert, key := genServerCert(t, "10.9.0.2")
	wsURL := "wss://10.9.0.2:51820/wg"

	wgS := l.startDaemon(nsS, nil)
	l.uapiSet(wgS, fmt.Sprintf("private_key=%s\nws_listen=%s\nws_server_tls_cert=%s\nws_server_tls_key=%s\npublic_key=%s\ntransport=websocket\nallowed_ip=10.10.0.1/32\n", privS, wsURL, cert, key, pubC))
	l.ifup(nsS, wgS, "10.10.0.2/24")

	wgC := l.startDaemon(nsC, nil)
	// Full-tunnel: the client peer catches everything.
	l.uapiSet(wgC, fmt.Sprintf("private_key=%s\npublic_key=%s\ntransport=websocket\nendpoint=10.9.0.2:51820\nws_url=%s\nws_tls_ca=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1\n", privC, pubS, wsURL, cert))
	l.ifup(nsC, wgC, "10.10.0.1/24")

	if !l.ping(nsC, "10.10.0.2") {
		t.Fatal("baseline ping (before full-tunnel routing) failed")
	}

	// Now install wg-quick's full-tunnel routing: set the fwmark on the (already
	// connected) socket, then route everything NOT carrying the mark into the tunnel.
	l.uapiSet(wgC, "fwmark=51820\n")
	l.run("ip", "-n", nsC, "rule", "add", "not", "fwmark", "51820", "table", "51820")
	l.run("ip", "-n", nsC, "route", "add", "default", "dev", wgC, "table", "51820")

	// The WS transport socket to 10.9.0.2 must now carry the mark (re-marked live by
	// SetMark) and escape the `not fwmark` rule; without the fix it self-loops.
	if !l.ping(nsC, "10.10.0.2") {
		t.Fatal("ping through the WebSocket FULL-TUNNEL failed (WS socket not re-marked?)")
	}
}

func TestE2E_MixedPeers(t *testing.T) {
	l := newLab(t)
	br := l.addBridge()
	nsC := l.addNS() // client with a UDP peer AND a WS peer
	nsU := l.addNS() // UDP server
	nsW := l.addNS() // WS server
	l.vethToBridge(nsC, br, "10.9.0.1/24")
	l.vethToBridge(nsU, br, "10.9.0.2/24")
	l.vethToBridge(nsW, br, "10.9.0.4/24")

	privC, pubC := genKeypair(t)
	privU, pubU := genKeypair(t)
	privW, pubW := genKeypair(t)
	cert, key := genServerCert(t, "10.9.0.4")
	wsURL := "wss://10.9.0.4:51820/wg"

	// UDP server (tunnel 10.10.0.2).
	wgU := l.startDaemon(nsU, nil)
	l.uapiSet(wgU, fmt.Sprintf("private_key=%s\nlisten_port=51820\npublic_key=%s\ntransport=udp\nallowed_ip=10.10.0.1/32\n", privU, pubC))
	l.ifup(nsU, wgU, "10.10.0.2/24")

	// WS server (tunnel 10.10.0.3).
	wgW := l.startDaemon(nsW, nil)
	l.uapiSet(wgW, fmt.Sprintf("private_key=%s\nws_listen=%s\nws_server_tls_cert=%s\nws_server_tls_key=%s\npublic_key=%s\ntransport=websocket\nallowed_ip=10.10.0.1/32\n", privW, wsURL, cert, key, pubC))
	l.ifup(nsW, wgW, "10.10.0.3/24")

	// One client device, both peers at once.
	wgC := l.startDaemon(nsC, nil)
	l.uapiSet(wgC, fmt.Sprintf(
		"private_key=%s\n"+
			"public_key=%s\ntransport=udp\nendpoint=10.9.0.2:51820\nallowed_ip=10.10.0.2/32\npersistent_keepalive_interval=1\n"+
			"public_key=%s\ntransport=websocket\nendpoint=10.9.0.4:51820\nws_url=%s\nws_tls_ca=%s\nallowed_ip=10.10.0.3/32\npersistent_keepalive_interval=1\n",
		privC, pubU, pubW, wsURL, cert))
	l.ifup(nsC, wgC, "10.10.0.1/24")

	if !l.ping(nsC, "10.10.0.2") {
		t.Fatal("ping through the UDP peer failed (mixed device)")
	}
	if !l.ping(nsC, "10.10.0.3") {
		t.Fatal("ping through the WebSocket peer failed (mixed device)")
	}
}

// TestE2E_Wstunnel covers the default unmasked path; TestE2E_WstunnelMasked covers the
// opt-in ws_mask path, where the wstunnel server MUST run --websocket-mask-frame.
func TestE2E_Wstunnel(t *testing.T)       { runWstunnelE2E(t, false) }
func TestE2E_WstunnelMasked(t *testing.T) { runWstunnelE2E(t, true) }

// TestE2E_Wstunnel_FullTunnel is the wstunnel-transport counterpart of
// TestE2E_WebSocket_FullTunnel: under wg-quick's fwmark + `ip rule not fwmark`, the TCP
// socket to the wstunnel relay must carry the mark or it self-loops into the tun.
func TestE2E_Wstunnel_FullTunnel(t *testing.T) {
	l := newLab(t)
	br := l.addBridge()
	nsC := l.addNS() // client, 10.9.0.1
	nsW := l.addNS() // wstunnel, 10.9.0.3
	nsS := l.addNS() // udp wg server, 10.9.0.2
	l.vethToBridge(nsC, br, "10.9.0.1/24")
	l.vethToBridge(nsW, br, "10.9.0.3/24")
	l.vethToBridge(nsS, br, "10.9.0.2/24")

	privC, pubC := genKeypair(t)
	privS, pubS := genKeypair(t)

	// Plain-UDP wg server (the real endpoint wstunnel forwards to).
	wgS := l.startDaemon(nsS, nil)
	l.uapiSet(wgS, fmt.Sprintf("private_key=%s\nlisten_port=51820\npublic_key=%s\ntransport=udp\nallowed_ip=10.10.0.1/32\n", privS, pubC))
	l.ifup(nsS, wgS, "10.10.0.2/24")

	l.startWstunnel(nsW, "ws://10.9.0.3:8080", "10.9.0.2:51820")

	// wg WebSocket client in wstunnel mode, full-tunnel (catches everything).
	wgC := l.startDaemon(nsC, nil)
	l.uapiSet(wgC, fmt.Sprintf(
		"private_key=%s\npublic_key=%s\ntransport=wstunnel\nendpoint=10.9.0.3:8080\nws_url=ws://10.9.0.3:8080/v1\nwstunnel_target=10.9.0.2:51820\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1\n",
		privC, pubS))
	l.ifup(nsC, wgC, "10.10.0.1/24")

	if !l.ping(nsC, "10.10.0.2") {
		t.Fatal("baseline ping (before full-tunnel routing) failed")
	}

	// Install wg-quick's full-tunnel routing, then re-mark the live socket.
	l.uapiSet(wgC, "fwmark=51820\n")
	l.run("ip", "-n", nsC, "rule", "add", "not", "fwmark", "51820", "table", "51820")
	l.run("ip", "-n", nsC, "route", "add", "default", "dev", wgC, "table", "51820")

	if !l.ping(nsC, "10.10.0.2") {
		t.Fatal("ping through the wstunnel FULL-TUNNEL failed (relay socket not re-marked?)")
	}
}

func runWstunnelE2E(t *testing.T, masked bool) {
	l := newLab(t)
	br := l.addBridge()
	nsC := l.addNS() // client, 10.9.0.1
	nsW := l.addNS() // wstunnel, 10.9.0.3
	nsS := l.addNS() // udp wg server, 10.9.0.2
	l.vethToBridge(nsC, br, "10.9.0.1/24")
	l.vethToBridge(nsW, br, "10.9.0.3/24")
	l.vethToBridge(nsS, br, "10.9.0.2/24")

	privC, pubC := genKeypair(t)
	privS, pubS := genKeypair(t)

	// Plain-UDP wg server (the real endpoint wstunnel forwards to).
	wgS := l.startDaemon(nsS, nil)
	l.uapiSet(wgS, fmt.Sprintf("private_key=%s\nlisten_port=51820\npublic_key=%s\ntransport=udp\nallowed_ip=10.10.0.1/32\n", privS, pubC))
	l.ifup(nsS, wgS, "10.10.0.2/24")

	// wstunnel + client masking must agree: masked client <-> --websocket-mask-frame server.
	var wstunnelArgs []string
	if masked {
		wstunnelArgs = []string{"--websocket-mask-frame"}
	}
	l.startWstunnel(nsW, "ws://10.9.0.3:8080", "10.9.0.2:51820", wstunnelArgs...)

	// wg WebSocket client in wstunnel mode through the real wstunnel.
	wgC := l.startDaemon(nsC, nil)
	maskLine := ""
	if masked {
		maskLine = "ws_mask=true\n"
	}
	l.uapiSet(wgC, fmt.Sprintf(
		"private_key=%s\npublic_key=%s\ntransport=wstunnel\nendpoint=10.9.0.3:8080\nws_url=ws://10.9.0.3:8080/v1\nwstunnel_target=10.9.0.2:51820\n%sallowed_ip=10.10.0.2/32\npersistent_keepalive_interval=1\n",
		privC, pubS, maskLine))
	l.ifup(nsC, wgC, "10.10.0.1/24")

	if !l.ping(nsC, "10.10.0.2") {
		t.Fatalf("ping through the wstunnel tunnel failed (masked=%v)", masked)
	}
}
