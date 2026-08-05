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

func TestE2E_UDP(t *testing.T) {
	l := newLab(t)
	br := l.addBridge()
	nsC := l.addNS()
	nsS := l.addNS()
	l.vethToBridge(nsC, br, "10.9.0.1/24")
	l.vethToBridge(nsS, br, "10.9.0.2/24")

	privC, pubC := genKeypair(t)
	privS, pubS := genKeypair(t)

	wgS := l.startDaemon(nsS, []string{"WG_TRANSPORT=udp"})
	l.uapiSet(wgS, fmt.Sprintf("private_key=%s\nlisten_port=51820\npublic_key=%s\nallowed_ip=10.10.0.1/32\n", privS, pubC))
	l.ifup(nsS, wgS, "10.10.0.2/24")

	wgC := l.startDaemon(nsC, []string{"WG_TRANSPORT=udp"})
	l.uapiSet(wgC, fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=10.9.0.2:51820\nallowed_ip=10.10.0.2/32\npersistent_keepalive_interval=1\n", privC, pubS))
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

	wgS := l.startDaemon(nsS, []string{"WG_TRANSPORT=ws", "WG_WS_ROLE=server", "WG_WS_TLS_CERT=" + cert, "WG_WS_TLS_KEY=" + key})
	l.uapiSet(wgS, fmt.Sprintf("private_key=%s\nws_listen=wss://10.9.0.2:51820/wg\npublic_key=%s\nallowed_ip=10.10.0.1/32\n", privS, pubC))
	l.ifup(nsS, wgS, "10.10.0.2/24")

	wgC := l.startDaemon(nsC, []string{"WG_TRANSPORT=ws", "WG_WS_TLS_CA=" + cert})
	l.uapiSet(wgC, fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=wss://10.9.0.2:51820/wg\nallowed_ip=10.10.0.2/32\npersistent_keepalive_interval=1\n", privC, pubS))
	l.ifup(nsC, wgC, "10.10.0.1/24")

	if !l.ping(nsC, "10.10.0.2") {
		t.Fatal("ping through the WebSocket tunnel failed")
	}
}

// TestE2E_Wstunnel covers the default unmasked path; TestE2E_WstunnelMasked covers the
// opt-in ws_mask path, where the wstunnel server MUST run --websocket-mask-frame to
// unmask the client's masked frames (mask modes must match).
func TestE2E_Wstunnel(t *testing.T)       { runWstunnelE2E(t, false) }
func TestE2E_WstunnelMasked(t *testing.T) { runWstunnelE2E(t, true) }

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
	wgS := l.startDaemon(nsS, []string{"WG_TRANSPORT=udp"})
	l.uapiSet(wgS, fmt.Sprintf("private_key=%s\nlisten_port=51820\npublic_key=%s\nallowed_ip=10.10.0.1/32\n", privS, pubC))
	l.ifup(nsS, wgS, "10.10.0.2/24")

	// wstunnel + client masking must agree: masked client <-> --websocket-mask-frame server.
	var wstunnelArgs []string
	clientEnv := []string{"WG_TRANSPORT=ws"}
	if masked {
		wstunnelArgs = []string{"--websocket-mask-frame"}
		clientEnv = append(clientEnv, "WG_WS_MASK=1")
	}
	l.startWstunnel(nsW, "ws://10.9.0.3:8080", "10.9.0.2:51820", wstunnelArgs...)

	// wg WebSocket client in wstunnel mode through the real wstunnel.
	wgC := l.startDaemon(nsC, clientEnv)
	l.uapiSet(wgC, fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=ws://10.9.0.3:8080/v1\nws_mode=wstunnel\nwstunnel_target=10.9.0.2:51820\nallowed_ip=10.10.0.2/32\npersistent_keepalive_interval=1\n", privC, pubS))
	l.ifup(nsC, wgC, "10.10.0.1/24")

	if !l.ping(nsC, "10.10.0.2") {
		t.Fatalf("ping through the wstunnel tunnel failed (masked=%v)", masked)
	}
}
