/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
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

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// fakeWstunnel is an in-process stand-in for a default wstunnel server. unmask=false
// (default) mirrors wstunnel's auto_apply_mask=false: it does NOT unmask client frames.
type fakeWstunnel struct {
	srv    *httptest.Server
	unmask bool
}

func newFakeWstunnel(t *testing.T, unmask bool) *fakeWstunnel {
	t.Helper()
	f := &fakeWstunnel{unmask: unmask}
	mux := http.NewServeMux() // only /v1/events is served; any other path => 404
	mux.HandleFunc("/v1/events", func(w http.ResponseWriter, r *http.Request) {
		target, err := targetFromWstunnelSubproto(r.Header.Get("Sec-WebSocket-Protocol"))
		if err != nil {
			http.Error(w, "bad token", http.StatusBadRequest)
			return
		}
		c, rw, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		f.relay(c, rw.Reader, target)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeWstunnel) url() string { return "ws" + strings.TrimPrefix(f.srv.URL, "http") }

// targetFromWstunnelSubproto pulls r:rp out of the "v1, authorization.bearer.<jwt>"
// subprotocol by base64-decoding the JWT payload segment (no signature check, like wstunnel).
func targetFromWstunnelSubproto(h string) (string, error) {
	const p = "authorization.bearer."
	i := strings.Index(h, p)
	if i < 0 {
		return "", errors.New("no bearer subprotocol")
	}
	tok := strings.TrimSpace(h[i+len(p):])
	seg := strings.Split(tok, ".")
	if len(seg) != 3 {
		return "", errors.New("malformed jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(seg[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		R  string `json:"r"`
		RP int    `json:"rp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	if claims.R == "" || claims.RP == 0 {
		return "", errors.New("empty r/rp")
	}
	return fmt.Sprintf("%s:%d", claims.R, claims.RP), nil
}

func (f *fakeWstunnel) relay(c net.Conn, br *bufio.Reader, target string) {
	defer c.Close()
	uc, err := net.Dial("udp", target)
	if err != nil {
		return
	}
	defer uc.Close()
	var wmu sync.Mutex
	writeWS := func(op ws.OpCode, p []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return ws.WriteFrame(c, ws.NewFrame(op, true, p))
	}
	go func() { // UDP -> WS (server frames are always unmasked)
		buf := make([]byte, 1<<16)
		for {
			n, err := uc.Read(buf)
			if err != nil {
				return
			}
			if writeWS(ws.OpBinary, buf[:n]) != nil {
				return
			}
		}
	}()
	for { // WS -> UDP
		h, err := ws.ReadHeader(br)
		if err != nil || h.Length > 1<<16 {
			return
		}
		p := make([]byte, h.Length)
		if _, err := io.ReadFull(br, p); err != nil {
			return
		}
		if h.Masked && f.unmask { // default (unmask=false) forwards masked bytes AS-IS
			ws.Cipher(p, h.Mask, 0)
		}
		switch h.OpCode {
		case ws.OpBinary:
			if _, err := uc.Write(p); err != nil {
				return
			}
		case ws.OpPing:
			if writeWS(ws.OpPong, p) != nil {
				return
			}
		case ws.OpClose:
			return
		}
	}
}

// newUDPServerDevice brings up a plain-UDP WireGuard device (the real endpoint the fake
// wstunnel forwards to) and returns its TUN and actual UDP port.
func newUDPServerDevice(t *testing.T, selfPriv, peerPub string) (*tuntest.ChannelTUN, int) {
	t.Helper()
	tdev := tuntest.NewChannelTUN()
	d := device.NewDevice(tdev.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=1.0.0.1/32\n", selfPriv, peerPub)
	if err := d.IpcSet(cfg); err != nil {
		t.Fatalf("server IpcSet: %v", err)
	}
	if err := d.Up(); err != nil {
		t.Fatalf("server Up: %v", err)
	}
	t.Cleanup(d.Close)
	return tdev, listenPortOf(t, d)
}

// newWSClientDevice brings up a WebSocket client WireGuard device in wstunnel mode,
// dialing endpoint and asking the relay to forward to target (host:port).
func newWSClientDevice(t *testing.T, selfPriv, peerPub, endpoint, target string, opts ...conn.WSOption) *tuntest.ChannelTUN {
	t.Helper()
	tdev := tuntest.NewChannelTUN()
	all := append([]conn.WSOption{conn.WithWSRole(conn.WSRoleClient)}, opts...)
	bind, err := conn.NewWebSocketBind(all...)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	d := device.NewDevice(tdev.TUN(), bind, device.NewLogger(device.LogLevelError, ""))
	cfg := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nws_mode=wstunnel\nws_target=%s\nallowed_ip=1.0.0.2/32\npersistent_keepalive_interval=1\n",
		selfPriv, peerPub, endpoint, target)
	if err := d.IpcSet(cfg); err != nil {
		t.Fatalf("client IpcSet: %v", err)
	}
	if err := d.Up(); err != nil {
		t.Fatalf("client Up: %v", err)
	}
	t.Cleanup(d.Close)
	return tdev
}

// wsAssertPingFails sends pings for the window and fails if any transits (the handshake
// is expected NOT to complete). Because the failure mode is deterministic (garbage
// datagrams or a 404 upgrade), a completed ping means the guard did not hold.
func wsAssertPingFails(t *testing.T, from, to *tuntest.ChannelTUN, fromIP, toIP [4]byte, window time.Duration) {
	t.Helper()
	msg := tuntest.Ping(netip.AddrFrom4(toIP), netip.AddrFrom4(fromIP))
	deadline := time.After(window)
	for {
		select {
		case <-deadline:
			return // good: nothing transited
		default:
		}
		from.Outbound <- msg
		select {
		case got := <-to.Inbound:
			if bytes.Equal(got, msg) {
				t.Fatal("ping transited, but the handshake should have failed")
			}
		case <-time.After(200 * time.Millisecond):
		case <-deadline:
			return
		}
	}
}

func wstunnelTarget(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) }

func TestWstunnelMode_UnmaskedDefault_Handshake(t *testing.T) {
	priv1, pub1 := wgKeypair(t)
	priv2, pub2 := wgKeypair(t)
	srv, port := newUDPServerDevice(t, priv2, pub1)
	fake := newFakeWstunnel(t, false) // default wstunnel: does NOT unmask
	cli := newWSClientDevice(t, priv1, pub2, fake.url(), wstunnelTarget(port))
	wsAssertPing(t, cli, srv, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 2}, 10*time.Second)
}

func TestWstunnelMode_MaskedVsDefaultServer_Fails(t *testing.T) {
	priv1, pub1 := wgKeypair(t)
	priv2, pub2 := wgKeypair(t)
	srv, port := newUDPServerDevice(t, priv2, pub1)
	fake := newFakeWstunnel(t, false) // does NOT unmask -> masked client => garbage
	cli := newWSClientDevice(t, priv1, pub2, fake.url(), wstunnelTarget(port), conn.WithWSMask(true))
	wsAssertPingFails(t, cli, srv, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 2}, 3*time.Second)
}

func TestWstunnelMode_MaskedVsMaskingServer_Handshake(t *testing.T) {
	priv1, pub1 := wgKeypair(t)
	priv2, pub2 := wgKeypair(t)
	srv, port := newUDPServerDevice(t, priv2, pub1)
	fake := newFakeWstunnel(t, true) // --websocket-mask-frame: unmasks
	cli := newWSClientDevice(t, priv1, pub2, fake.url(), wstunnelTarget(port), conn.WithWSMask(true))
	wsAssertPing(t, cli, srv, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 2}, 10*time.Second)
}

func TestWstunnelMode_WrongPrefix_NoHandshake(t *testing.T) {
	priv1, pub1 := wgKeypair(t)
	priv2, pub2 := wgKeypair(t)
	srv, port := newUDPServerDevice(t, priv2, pub1)
	fake := newFakeWstunnel(t, false)
	// endpoint with a non-v1 path => /wrong/events, which the fake serves 404 for.
	cli := newWSClientDevice(t, priv1, pub2, fake.url()+"/wrong", wstunnelTarget(port))
	wsAssertPingFails(t, cli, srv, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 2}, 3*time.Second)
}
