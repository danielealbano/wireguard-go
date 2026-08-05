/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// wsBridge is a test WebSocket relay built on gobwas/ws. In relay mode it pairs the
// first two accepted connections and forwards every binary message from each to the
// other; in echo mode it reflects frames back. It accepts masked or unmasked client
// frames and always writes UNMASKED (mirroring a default wstunnel server). It answers
// pings with pongs. Accepted peers are tracked so a test can force-drop them.
type wsPeer struct {
	conn net.Conn
	wmu  sync.Mutex // serialises writes: relay (other goroutine) + ping-reply (own goroutine)
}

type wsBridge struct {
	srv  *httptest.Server
	echo bool

	mu    sync.Mutex
	peers []*wsPeer
}

func newWSBridge(t *testing.T, useTLS, echo bool) *wsBridge {
	t.Helper()
	b := &wsBridge{echo: echo}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, rw, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		p := &wsPeer{conn: c}
		b.mu.Lock()
		b.peers = append(b.peers, p)
		b.mu.Unlock()
		b.serve(p, rw.Reader)
	})
	if useTLS {
		b.srv = httptest.NewTLSServer(h)
	} else {
		b.srv = httptest.NewServer(h)
	}
	t.Cleanup(b.srv.Close)
	return b
}

func (p *wsPeer) write(op ws.OpCode, payload []byte) {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_ = ws.WriteFrame(p.conn, ws.NewFrame(op, true, payload))
}

func (b *wsBridge) serve(p *wsPeer, r *bufio.Reader) {
	const bridgeReadLimit = 1 << 20 // trusted test frames; bounds allocation
	for {
		h, err := ws.ReadHeader(r)
		if err != nil || h.Length > bridgeReadLimit {
			return
		}
		payload := make([]byte, h.Length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return
		}
		if h.Masked {
			ws.Cipher(payload, h.Mask, 0)
		}
		switch h.OpCode {
		case ws.OpPing:
			p.write(ws.OpPong, payload)
			continue
		case ws.OpPong:
			continue
		case ws.OpClose:
			return
		case ws.OpBinary:
			// fall through to relay/echo
		default:
			continue
		}
		if b.echo {
			p.write(ws.OpBinary, payload)
			continue
		}
		b.mu.Lock()
		var other *wsPeer
		for _, q := range b.peers {
			if q != p {
				other = q
			}
		}
		b.mu.Unlock()
		if other != nil {
			other.write(ws.OpBinary, payload)
		}
	}
}

// url converts the httptest http(s):// base into ws(s)://.
func (b *wsBridge) url() string { return "ws" + strings.TrimPrefix(b.srv.URL, "http") }

// dropAll force-closes every accepted connection (reconnect tests).
func (b *wsBridge) dropAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.peers {
		_ = p.conn.Close()
	}
	b.peers = nil
}

func (b *wsBridge) clientTLS() *tls.Config {
	if b.srv.TLS == nil {
		return nil
	}
	cp := x509.NewCertPool()
	cp.AddCert(b.srv.Certificate())
	return &tls.Config{RootCAs: cp}
}

// newWSSilentServer upgrades then drains without ever ponging, so the client ping
// backstop must time out and reconnect.
func newWSSilentServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, c) // never parses/pongs; returns when the client closes
		_ = c.Close()
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

// newWSMaskProbe upgrades one client and reports the mask bit of the first binary
// frame it receives, so a test can assert the client bind's masking behaviour
// (unmasked by default; masked with WithWSMask(true)).
func newWSMaskProbe(t *testing.T) (url string, masked <-chan bool) {
	t.Helper()
	ch := make(chan bool, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, rw, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			h, err := ws.ReadHeader(rw.Reader)
			if err != nil {
				return
			}
			payload := make([]byte, h.Length)
			if _, err := io.ReadFull(rw.Reader, payload); err != nil {
				return
			}
			if h.OpCode == ws.OpBinary {
				select {
				case ch <- h.Masked:
				default:
				}
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), ch
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
// The returned bridge lets a test force a reconnect via dropAll.
func newWSDevicePair(t *testing.T, useTLS bool) (a, b *tuntest.ChannelTUN, bridge *wsBridge) {
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
	return a, b, br
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
