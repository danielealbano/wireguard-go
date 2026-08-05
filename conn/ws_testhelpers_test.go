/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// wsBridge is a test WebSocket relay. In relay mode it pairs the first two accepted
// connections and forwards every binary message from each to the other, so two
// client-role WebSocketBinds dialing it tunnel end-to-end. In echo mode it reflects
// frames back (dial/upgrade unit checks). It tracks accepted connections so a test
// can force-drop them (reconnect tests).
type wsBridge struct {
	srv  *httptest.Server
	echo bool

	mu    sync.Mutex
	peers []*websocket.Conn
}

func newWSBridge(t *testing.T, useTLS, echo bool) *wsBridge {
	t.Helper()
	b := &wsBridge{echo: echo}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		b.mu.Lock()
		b.peers = append(b.peers, c)
		b.mu.Unlock()
		b.serve(c)
	})
	if useTLS {
		b.srv = httptest.NewTLSServer(h)
	} else {
		b.srv = httptest.NewServer(h)
	}
	t.Cleanup(b.srv.Close)
	return b
}

func (b *wsBridge) serve(c *websocket.Conn) {
	ctx := context.Background()
	c.SetReadLimit(1 << 20) // allow oversize frames so the client-side guard is what drops them
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			continue
		}
		if b.echo {
			_ = c.Write(ctx, websocket.MessageBinary, data)
			continue
		}
		b.mu.Lock()
		var other *websocket.Conn
		for _, p := range b.peers {
			if p != c {
				other = p
			}
		}
		b.mu.Unlock()
		if other != nil {
			_ = other.Write(ctx, websocket.MessageBinary, data)
		}
	}
}

// url converts the httptest http(s):// base into ws(s)://.
func (b *wsBridge) url() string { return "ws" + strings.TrimPrefix(b.srv.URL, "http") }

func (b *wsBridge) clientTLS() *tls.Config {
	if b.srv.TLS == nil {
		return nil
	}
	cp := x509.NewCertPool()
	cp.AddCert(b.srv.Certificate())
	return &tls.Config{RootCAs: cp}
}

// wgKeypair returns a clamped Curve25519 private key and its public key, hex-encoded.
func wgKeypair(t *testing.T) (priv, pub string) {
	t.Helper()
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	return hex.EncodeToString(sk[:]), hex.EncodeToString(pk)
}

// newWSDevicePair brings up two WireGuard devices whose binds are client-role
// WebSocketBinds pointed at the same relay, so they tunnel over WebSocket.
// Persistent keepalive makes both dial promptly so the relay can pair them.
func newWSDevicePair(t *testing.T, useTLS bool) (a, b *tuntest.ChannelTUN) {
	t.Helper()
	br := newWSBridge(t, useTLS, false)
	priv1, pub1 := wgKeypair(t)
	priv2, pub2 := wgKeypair(t)
	mk := func(ip byte, selfPriv, peerPub string) *tuntest.ChannelTUN {
		tdev := tuntest.NewChannelTUN()
		wsb, err := conn.NewWebSocketBind(
			conn.WithWSRole(conn.WSRoleClient),
			conn.WithWSClientTLS(br.clientTLS()),
			conn.WithWSPingInterval(0),
		)
		if err != nil {
			t.Fatalf("bind: %v", err)
		}
		d := device.NewDevice(tdev.TUN(), wsb, device.NewLogger(device.LogLevelError, ""))
		cfg := fmt.Sprintf(
			"private_key=%s\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=1\nallowed_ip=1.0.0.%d/32\n",
			selfPriv, peerPub, br.url(), ip,
		)
		if err := d.IpcSet(cfg); err != nil {
			t.Fatalf("IpcSet: %v", err)
		}
		if err := d.Up(); err != nil {
			t.Fatalf("Up: %v", err)
		}
		t.Cleanup(d.Close)
		return tdev
	}
	// peer 1 allows peer 2's IP (1.0.0.2) and vice versa.
	a = mk(2, priv1, pub2)
	b = mk(1, priv2, pub1)
	return a, b
}

// wsAssertPing sends one ping from -> to and fails if it does not transit within
// the timeout (the tun stages the packet until the handshake completes).
func wsAssertPing(t *testing.T, from, to *tuntest.ChannelTUN, fromIP, toIP [4]byte, timeout time.Duration) {
	t.Helper()
	msg := tuntest.Ping(netip.AddrFrom4(toIP), netip.AddrFrom4(fromIP))
	deadline := time.After(timeout)
	for {
		from.Outbound <- msg
		select {
		case got := <-to.Inbound:
			if bytes.Equal(got, msg) {
				return
			}
		case <-time.After(300 * time.Millisecond):
			// retry: resend to drive handshake retransmission through the relay
		case <-deadline:
			t.Fatal("ping did not transit within timeout")
		}
		select {
		case <-deadline:
			t.Fatal("ping did not transit within timeout")
		default:
		}
	}
}
