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

// openServerBind opens a listening WebSocket bind on a free local address (via the
// device-level setters, as the UAPI does) and returns the bind, its ReceiveFunc,
// and the ws:// URL raw clients can dial.
func openServerBind(t *testing.T, bearer string, opts ...conn.WSOption) (*conn.WebSocketBind, conn.ReceiveFunc, string) {
	t.Helper()
	addr := freeLocalAddr(t)
	url := "ws://" + addr + "/wg"
	b, err := conn.NewWebSocketBind(opts...)
	if err != nil {
		t.Fatalf("server bind: %v", err)
	}
	if err := b.SetWSListen(url); err != nil {
		t.Fatalf("SetWSListen: %v", err)
	}
	if bearer != "" {
		b.SetServerBearer(bearer)
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	time.Sleep(50 * time.Millisecond) // let the listener come up before clients dial
	return b, fns[0], url
}

// rawWSClient is a raw gobwas WebSocket client used to drive the server bind directly.
type rawWSClient struct {
	conn net.Conn
	br   *bufio.Reader
	mask bool
}

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

func (c *rawWSClient) writeBinary(payload []byte) error {
	if c.mask {
		p := append([]byte(nil), payload...)
		return ws.WriteFrame(c.conn, ws.MaskFrameInPlace(ws.NewBinaryFrame(p)))
	}
	return ws.WriteFrame(c.conn, ws.NewBinaryFrame(payload))
}

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

// newWSServerTunnel brings up one listening device and n dialing devices. The server
// has one inbound peer per client (endpoints roam in on handshake). serverBearer (if
// set) gates the upgrade; clientBearer is presented by each client.
func newWSServerTunnel(t *testing.T, n int, serverBearer, clientBearer string) *wsServerTunnel {
	t.Helper()
	addr := freeLocalAddr(t)
	listenURL := "ws://" + addr + "/wg"

	serverPriv, serverPub := wgKeypair(t)
	clientKeys := make([][2]string, n)
	for i := range clientKeys {
		p, pub := wgKeypair(t)
		clientKeys[i] = [2]string{p, pub}
	}

	sbind, err := conn.NewWebSocketBind(conn.WithWSLogger(conn.Logger{}))
	if err != nil {
		t.Fatalf("server bind: %v", err)
	}
	stun := tuntest.NewChannelTUN()
	sdev := device.NewDevice(stun.TUN(), sbind, device.NewLogger(device.LogLevelError, ""))
	scfg := fmt.Sprintf("private_key=%s\nws_listen=%s\n", serverPriv, listenURL)
	if serverBearer != "" {
		scfg += "ws_server_bearer=" + serverBearer + "\n"
	}
	for i, k := range clientKeys {
		// inbound peers: transport=websocket, no ws_url/endpoint (learned on accept).
		scfg += fmt.Sprintf("public_key=%s\ntransport=websocket\nallowed_ip=1.0.0.%d/32\n", k[1], 2+i)
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
		cbind, err := conn.NewWebSocketBind(conn.WithWSLogger(conn.Logger{}))
		if err != nil {
			t.Fatalf("client bind %d: %v", i, err)
		}
		ctun := tuntest.NewChannelTUN()
		cdev := device.NewDevice(ctun.TUN(), cbind, device.NewLogger(device.LogLevelError, ""))
		ccfg := fmt.Sprintf(
			"private_key=%s\npublic_key=%s\ntransport=websocket\nendpoint=%s\nws_url=%s\npersistent_keepalive_interval=1\nallowed_ip=1.0.0.1/32\n",
			k[0], serverPub, addr, listenURL,
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

func TestWSServer_SimultaneousClientAndServer(t *testing.T) {
	// One device is BOTH a WS server (ws_listen) accepting an inbound peer AND a WS
	// client dialing an outbound peer — the roleless bind must do both at once.
	addr := freeLocalAddr(t)
	listenURL := "ws://" + addr + "/wg"

	// A separate plain server device the "hub" dials out to.
	outboundAddr := freeLocalAddr(t)
	outboundURL := "ws://" + outboundAddr + "/wg"

	hubPriv, hubPub := wgKeypair(t)
	inPriv, inPub := wgKeypair(t)   // dials into the hub
	outPriv, outPub := wgKeypair(t) // the hub dials out to this one

	// The outbound target: a listening device.
	obind, _ := conn.NewWebSocketBind(conn.WithWSLogger(conn.Logger{}))
	otun := tuntest.NewChannelTUN()
	odev := device.NewDevice(otun.TUN(), obind, device.NewLogger(device.LogLevelError, ""))
	t.Cleanup(odev.Close)
	mustSet(t, odev, fmt.Sprintf("private_key=%s\nws_listen=%s\npublic_key=%s\ntransport=websocket\nallowed_ip=1.0.0.1/32\n", outPriv, outboundURL, hubPub))
	mustUp(t, odev)

	// The hub: listens (for the inbound peer) AND dials the outbound peer.
	hbind, _ := conn.NewWebSocketBind(conn.WithWSLogger(conn.Logger{}))
	htun := tuntest.NewChannelTUN()
	hdev := device.NewDevice(htun.TUN(), hbind, device.NewLogger(device.LogLevelError, ""))
	t.Cleanup(hdev.Close)
	mustSet(t, hdev, fmt.Sprintf(
		"private_key=%s\nws_listen=%s\n"+
			"public_key=%s\ntransport=websocket\nallowed_ip=1.0.0.2/32\n"+ // inbound peer
			"public_key=%s\ntransport=websocket\nendpoint=%s\nws_url=%s\npersistent_keepalive_interval=1\nallowed_ip=1.0.0.3/32\n", // outbound peer
		hubPriv, listenURL, inPub, outPub, outboundAddr, outboundURL))
	mustUp(t, hdev)

	// The inbound client dials the hub.
	ibind, _ := conn.NewWebSocketBind(conn.WithWSLogger(conn.Logger{}))
	itun := tuntest.NewChannelTUN()
	idev := device.NewDevice(itun.TUN(), ibind, device.NewLogger(device.LogLevelError, ""))
	t.Cleanup(idev.Close)
	mustSet(t, idev, fmt.Sprintf("private_key=%s\npublic_key=%s\ntransport=websocket\nendpoint=%s\nws_url=%s\npersistent_keepalive_interval=1\nallowed_ip=1.0.0.1/32\n", inPriv, hubPub, addr, listenURL))
	mustUp(t, idev)

	// Inbound peer -> hub, and hub -> outbound peer both transit.
	wsAssertPing(t, itun, htun, [4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 1}, 10*time.Second)
	wsAssertPing(t, htun, otun, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 3}, 10*time.Second)
}

func mustSet(t *testing.T, d *device.Device, cfg string) {
	t.Helper()
	if err := d.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
}

func mustUp(t *testing.T, d *device.Device) {
	t.Helper()
	if err := d.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
}

// TestWSServer_ListenPersistsWhenSetconfOmitsWSListen locks in that ws_listen is a
// persistent device scalar, like listen_port: a later set=1 that omits it (wg's
// full-replace setconf path) must leave the running listener untouched.
func TestWSServer_ListenPersistsWhenSetconfOmitsWSListen(t *testing.T) {
	addr := freeLocalAddr(t)
	listenURL := "ws://" + addr + "/wg"

	serverPriv, serverPub := wgKeypair(t)
	aPriv, aPub := wgKeypair(t)
	bPriv, bPub := wgKeypair(t)

	sbind, err := conn.NewWebSocketBind(conn.WithWSLogger(conn.Logger{}))
	if err != nil {
		t.Fatalf("server bind: %v", err)
	}
	stun := tuntest.NewChannelTUN()
	sdev := device.NewDevice(stun.TUN(), sbind, device.NewLogger(device.LogLevelError, ""))
	t.Cleanup(sdev.Close)
	mustSet(t, sdev, fmt.Sprintf(
		"private_key=%s\nws_listen=%s\npublic_key=%s\ntransport=websocket\nallowed_ip=1.0.0.2/32\npublic_key=%s\ntransport=websocket\nallowed_ip=1.0.0.3/32\n",
		serverPriv, listenURL, aPub, bPub))
	mustUp(t, sdev)

	bringUpClient := func(priv string) *tuntest.ChannelTUN {
		t.Helper()
		cbind, err := conn.NewWebSocketBind(conn.WithWSLogger(conn.Logger{}))
		if err != nil {
			t.Fatalf("client bind: %v", err)
		}
		ctun := tuntest.NewChannelTUN()
		cdev := device.NewDevice(ctun.TUN(), cbind, device.NewLogger(device.LogLevelError, ""))
		t.Cleanup(cdev.Close)
		mustSet(t, cdev, fmt.Sprintf(
			"private_key=%s\npublic_key=%s\ntransport=websocket\nendpoint=%s\nws_url=%s\npersistent_keepalive_interval=1\nallowed_ip=1.0.0.1/32\n",
			priv, serverPub, addr, listenURL))
		mustUp(t, cdev)
		return ctun
	}

	atun := bringUpClient(aPriv)
	wsAssertPing(t, atun, stun, [4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 1}, 10*time.Second)

	// Full-replace setconf that OMITS ws_listen must not tear the listener down.
	mustSet(t, sdev, fmt.Sprintf(
		"replace_peers=true\npublic_key=%s\ntransport=websocket\nallowed_ip=1.0.0.2/32\npublic_key=%s\ntransport=websocket\nallowed_ip=1.0.0.3/32\n",
		aPub, bPub))

	btun := bringUpClient(bPriv)
	wsAssertPing(t, btun, stun, [4]byte{1, 0, 0, 3}, [4]byte{1, 0, 0, 1}, 10*time.Second)
}

func TestWSServer_BearerReject(t *testing.T) {
	ok := newWSServerTunnel(t, 1, "s3cret", "s3cret")
	wsAssertPing(t, ok.clientTUN[0], ok.serverTUN, [4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 1}, 10*time.Second)

	bad := newWSServerTunnel(t, 1, "s3cret", "wrong")
	msg := tuntest.Ping(netip.AddrFrom4([4]byte{1, 0, 0, 1}), netip.AddrFrom4([4]byte{1, 0, 0, 2}))
	bad.clientTUN[0].Outbound <- msg
	select {
	case <-bad.serverTUN.Inbound:
		t.Fatal("packet transited despite wrong bearer")
	case <-time.After(2 * time.Second):
	}
}

func TestWSServer_CloseShutsDown(t *testing.T) {
	b, fn, _ := openServerBind(t, "")
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
	_, fn, url := openServerBind(t, "")
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
	if ep1.DstToString() == ep2.DstToString() {
		t.Errorf("two clients shared an endpoint identity: %s", ep1.DstToString())
	}
	if len(ep1.DstToBytes()) == 0 || len(ep2.DstToBytes()) == 0 {
		t.Error("endpoint DstToBytes empty (needed for MAC2 cookies)")
	}
}

func TestWSServer_Roaming(t *testing.T) {
	b, fn, url := openServerBind(t, "")
	c1 := rawDial(t, url, "", false)
	if err := c1.writeBinary([]byte{1}); err != nil {
		t.Fatalf("c1 write: %v", err)
	}
	oldEP := recvEndpoint(t, fn)
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
	_, _, url := openServerBind(t, secret, conn.WithWSLogger(conn.Logger{Verbosef: logf, Errorf: logf}))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
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
	b, err := conn.NewWebSocketBind(conn.WithWSLogger(conn.Logger{}))
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := b.SetWSListen("ws://" + addr + "/wg"); err != nil {
		t.Fatalf("SetWSListen: %v", err)
	}
	for i := 0; i < 50; i++ {
		if _, _, err := b.Open(0); err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		if err := b.Close(); err != nil {
			t.Fatalf("Close %d: %v", i, err)
		}
	}
}

func TestWSServer_OpenWithoutListenURL(t *testing.T) {
	// A bind opened before ws_listen is configured must bring up a receiver with no
	// HTTP server (a device can go Up first) and never panic in ServeMux.
	b, err := conn.NewWebSocketBind(conn.WithWSLogger(conn.Logger{}))
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open with no ws_listen: %v", err)
	}
	if len(fns) == 0 {
		t.Fatal("expected a receive func even without a listener")
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
