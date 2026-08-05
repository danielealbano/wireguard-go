/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func freeLocalAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

type wsServerTunnel struct {
	serverTUN *tuntest.ChannelTUN
	clientTUN []*tuntest.ChannelTUN
}

// newWSServerTunnel brings up one server-role device and n client-role devices that
// dial it. serverBearer (if non-empty) gates the upgrade; clientBearer is presented
// by each client. When they mismatch, clients cannot complete a handshake.
func newWSServerTunnel(t *testing.T, n int, serverBearer, clientBearer string) *wsServerTunnel {
	t.Helper()
	addr := freeLocalAddr(t)
	listenURL := "ws://" + addr + "/wg"

	serverPriv, serverPub := wgKeypair(t)
	clientKeys := make([][2]string, n) // [priv, pub]
	for i := range clientKeys {
		p, pub := wgKeypair(t)
		clientKeys[i] = [2]string{p, pub}
	}

	// Server device: one peer per client (endpoints roam in on handshake).
	serverOpts := []conn.WSOption{conn.WithWSRole(conn.WSRoleServer), conn.WithWSListenURL(listenURL), conn.WithWSPingInterval(0)}
	if serverBearer != "" {
		serverOpts = append(serverOpts, conn.WithWSServerBearer(serverBearer))
	}
	sbind, err := conn.NewWebSocketBind(serverOpts...)
	if err != nil {
		t.Fatalf("server bind: %v", err)
	}
	stun := tuntest.NewChannelTUN()
	sdev := device.NewDevice(stun.TUN(), sbind, device.NewLogger(device.LogLevelError, ""))
	scfg := fmt.Sprintf("private_key=%s\nws_listen=%s\n", serverPriv, listenURL)
	for i, k := range clientKeys {
		scfg += fmt.Sprintf("public_key=%s\nallowed_ip=1.0.0.%d/32\n", k[1], 2+i)
	}
	if err := sdev.IpcSet(scfg); err != nil {
		t.Fatalf("server IpcSet: %v", err)
	}
	if err := sdev.Up(); err != nil {
		t.Fatalf("server Up: %v", err)
	}
	t.Cleanup(sdev.Close)

	tun := &wsServerTunnel{serverTUN: stun}
	for i, k := range clientKeys {
		cbind, err := conn.NewWebSocketBind(conn.WithWSRole(conn.WSRoleClient), conn.WithWSPingInterval(0))
		if err != nil {
			t.Fatalf("client bind %d: %v", i, err)
		}
		ctun := tuntest.NewChannelTUN()
		cdev := device.NewDevice(ctun.TUN(), cbind, device.NewLogger(device.LogLevelError, ""))
		ccfg := fmt.Sprintf(
			"private_key=%s\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=1\nallowed_ip=1.0.0.1/32\n",
			k[0], serverPub, listenURL,
		)
		if clientBearer != "" {
			ccfg += "ws_bearer=" + clientBearer + "\n"
		}
		if err := cdev.IpcSet(ccfg); err != nil {
			t.Fatalf("client %d IpcSet: %v", i, err)
		}
		if err := cdev.Up(); err != nil {
			t.Fatalf("client %d Up: %v", i, err)
		}
		t.Cleanup(cdev.Close)
		tun.clientTUN = append(tun.clientTUN, ctun)
	}
	return tun
}

func TestWSServer_MultiClient(t *testing.T) {
	tun := newWSServerTunnel(t, 2, "", "")
	for i, ct := range tun.clientTUN {
		clientIP := [4]byte{1, 0, 0, byte(2 + i)}
		serverIP := [4]byte{1, 0, 0, 1}
		wsAssertPing(t, ct, tun.serverTUN, clientIP, serverIP, 10*time.Second)
	}
}

func TestWSServer_BearerReject(t *testing.T) {
	// Matching bearer: tunnel works.
	ok := newWSServerTunnel(t, 1, "s3cret", "s3cret")
	wsAssertPing(t, ok.clientTUN[0], ok.serverTUN, [4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 1}, 10*time.Second)

	// Wrong bearer: the upgrade is rejected, so no handshake completes.
	bad := newWSServerTunnel(t, 1, "s3cret", "wrong")
	msg := tuntest.Ping(netip.AddrFrom4([4]byte{1, 0, 0, 1}), netip.AddrFrom4([4]byte{1, 0, 0, 2}))
	bad.clientTUN[0].Outbound <- msg
	select {
	case <-bad.serverTUN.Inbound:
		t.Fatal("packet transited despite wrong bearer")
	case <-time.After(2 * time.Second):
		// expected: nothing gets through
	}
}
