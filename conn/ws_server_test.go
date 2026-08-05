/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
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

// openServerBind opens a server-role WebSocket bind on a free local address and
// returns the bind, its single ReceiveFunc, and the ws:// URL raw clients can dial.
func openServerBind(t *testing.T, opts ...conn.WSOption) (*conn.WebSocketBind, conn.ReceiveFunc, string) {
	t.Helper()
	addr := freeLocalAddr(t)
	url := "ws://" + addr + "/wg"
	all := append([]conn.WSOption{conn.WithWSRole(conn.WSRoleServer), conn.WithWSListenURL(url)}, opts...)
	b, err := conn.NewWebSocketBind(all...)
	if err != nil {
		t.Fatalf("server bind: %v", err)
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	// Give the listener a moment to come up before clients dial.
	time.Sleep(50 * time.Millisecond)
	return b, fns[0], url
}

// rawWSClient is a raw gobwas WebSocket client used to drive the server bind directly.
// mask selects whether its data frames are masked (default unmasked, like wstunnel).
type rawWSClient struct {
	conn net.Conn
	br   *bufio.Reader
	mask bool
}

// rawDial connects a plain WebSocket client, writing an optional bearer.
func rawDial(t *testing.T, url, bearer string, mask bool) *rawWSClient {
	t.Helper()
	hdr := http.Header{}
	if bearer != "" {
		hdr.Set("Authorization", "Bearer "+bearer)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, br, _, err := ws.Dialer{Header: ws.HandshakeHeaderHTTP(hdr)}.Dial(ctx, url)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &rawWSClient{conn: c, br: br, mask: mask}
}

// writeBinary sends one binary frame, masked per c.mask (copying first when masking,
// because MaskFrameInPlace mutates the payload).
func (c *rawWSClient) writeBinary(payload []byte) error {
	if c.mask {
		p := append([]byte(nil), payload...)
		return ws.WriteFrame(c.conn, ws.MaskFrameInPlace(ws.NewBinaryFrame(p)))
	}
	return ws.WriteFrame(c.conn, ws.NewBinaryFrame(payload))
}

// recvEndpoint drains one message from the server ReceiveFunc and returns its endpoint.
func recvEndpoint(t *testing.T, fn conn.ReceiveFunc) conn.Endpoint {
	t.Helper()
	type res struct {
		ep  conn.Endpoint
		err error
	}
	ch := make(chan res, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		eps := make([]conn.Endpoint, 1)
		n, err := fn(bufs, make([]int, 1), eps)
		if err != nil || n == 0 {
			ch <- res{nil, err}
			return
		}
		ch <- res{eps[0], nil}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("receive: %v", r.err)
		}
		return r.ep
	case <-time.After(3 * time.Second):
		t.Fatal("no message received")
		return nil
	}
}

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

func TestWSServer_CloseShutsDown(t *testing.T) {
	b, fn, _ := openServerBind(t)
	errc := make(chan error, 1)
	go func() {
		_, err := fn([][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1))
		errc <- err
	}()
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("receive after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock the receive func")
	}
}

func TestWSServer_PerClientDstIdentity(t *testing.T) {
	_, fn, url := openServerBind(t)

	c1 := rawDial(t, url, "", false)
	if err := c1.writeBinary([]byte{1}); err != nil {
		t.Fatalf("c1 write: %v", err)
	}
	ep1 := recvEndpoint(t, fn)

	c2 := rawDial(t, url, "", false)
	if err := c2.writeBinary([]byte{2}); err != nil {
		t.Fatalf("c2 write: %v", err)
	}
	ep2 := recvEndpoint(t, fn)

	// Distinct connections must yield distinct per-client identities (source
	// ip:port), so the rate-limiter and MAC2 cookies stay per-client.
	if ep1.DstToString() == ep2.DstToString() {
		t.Errorf("two clients shared an endpoint identity: %s", ep1.DstToString())
	}
	if len(ep1.DstToBytes()) == 0 || len(ep2.DstToBytes()) == 0 {
		t.Error("endpoint DstToBytes empty (needed for MAC2 cookies)")
	}
}

func TestWSServer_Roaming(t *testing.T) {
	b, fn, url := openServerBind(t)

	c1 := rawDial(t, url, "", false)
	if err := c1.writeBinary([]byte{1}); err != nil {
		t.Fatalf("c1 write: %v", err)
	}
	oldEP := recvEndpoint(t, fn)

	// Reconnect on a new TCP connection (roaming): the server allocates a new
	// connection id, so a Send to the new endpoint succeeds while the old one fails.
	_ = c1.conn.Close()
	c2 := rawDial(t, url, "", false)
	if err := c2.writeBinary([]byte{2}); err != nil {
		t.Fatalf("c2 write: %v", err)
	}
	newEP := recvEndpoint(t, fn)

	if err := b.Send([][]byte{{9}}, newEP); err != nil {
		t.Errorf("Send to the roamed (new) connection failed: %v", err)
	}
	if err := b.Send([][]byte{{9}}, oldEP); err == nil {
		t.Error("Send to the stale (old) connection should fail")
	}
}

func TestWSServer_BearerNotLogged(t *testing.T) {
	var buf strings.Builder
	var mu sync.Mutex
	logf := func(format string, args ...any) {
		mu.Lock()
		fmt.Fprintf(&buf, format, args...)
		mu.Unlock()
	}
	const secret = "top-secret-bearer"
	_, _, url := openServerBind(t,
		conn.WithWSServerBearer(secret),
		conn.WithWSLogger(conn.Logger{Verbosef: logf, Errorf: logf}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Rejected upgrade (wrong bearer) and an accepted one (correct bearer).
	badConn, _, _, err := ws.Dialer{
		Header: ws.HandshakeHeaderHTTP(http.Header{"Authorization": []string{"Bearer wrong"}}),
	}.Dial(ctx, url)
	if badConn != nil {
		_ = badConn.Close()
	}
	if err == nil {
		t.Fatal("upgrade with wrong bearer should be rejected")
	}
	okc := rawDial(t, url, secret, false)
	_ = okc.writeBinary([]byte{1})
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	logged := buf.String()
	mu.Unlock()
	if strings.Contains(logged, secret) {
		t.Errorf("server bearer leaked into logs:\n%s", logged)
	}
}

func TestWSServer_OpenCloseStress(t *testing.T) {
	addr := freeLocalAddr(t)
	b, err := conn.NewWebSocketBind(
		conn.WithWSRole(conn.WSRoleServer),
		conn.WithWSListenURL("ws://"+addr+"/wg"),
	)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	// Tight Open/Close cycles (no settle sleep) exercise the serve-goroutine vs
	// Close window that a BindUpdate performs; must be race-clean and panic-free.
	for i := 0; i < 50; i++ {
		if _, _, err := b.Open(0); err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		if err := b.Close(); err != nil {
			t.Fatalf("Close %d: %v", i, err)
		}
	}
}
