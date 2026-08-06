/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"golang.zx2c4.com/wireguard/conn"
)

// drainReceiver consumes from a ReceiveFunc until it errors (bind closed), so the
// client bind's read/queue path keeps flowing while a test drives Send.
func drainReceiver(fn conn.ReceiveFunc) {
	for {
		bufs := [][]byte{make([]byte, 2048)}
		if _, err := fn(bufs, make([]int, 1), make([]conn.Endpoint, 1)); err != nil {
			return
		}
	}
}

// recvData reads one message from a server ReceiveFunc, returning its payload, or
// nil if nothing arrives within timeout.
func recvData(t *testing.T, fn conn.ReceiveFunc, timeout time.Duration) []byte {
	t.Helper()
	type res struct {
		data []byte
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		n, err := fn(bufs, sizes, make([]conn.Endpoint, 1))
		if err != nil || n == 0 {
			ch <- res{nil, err}
			return
		}
		ch <- res{append([]byte(nil), bufs[0][:sizes[0]]...), nil}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("receive: %v", r.err)
		}
		return r.data
	case <-time.After(timeout):
		return nil
	}
}

func assertClientMask(t *testing.T, mask bool) {
	t.Helper()
	url, masked := newWSMaskProbe(t)
	b := newClientBind(t)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	go drainReceiver(fns[0])
	ep, err := b.ParseWSPeerEndpoint(conn.WSPeerConfig{
		Endpoint:  netip.MustParseAddrPort(wsURLHost(t, url)),
		Transport: "websocket",
		URL:       url,
		Mask:      mask,
	})
	if err != nil {
		t.Fatalf("ParseWSPeerEndpoint: %v", err)
	}
	if err := b.Send([][]byte{{1, 2, 3}}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case got := <-masked:
		if got != mask {
			t.Errorf("client frame masked=%v, want %v", got, mask)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("mask probe received no binary frame")
	}
}

func TestWSClient_UnmaskedByDefault(t *testing.T) { assertClientMask(t, false) }

func TestWSClient_MaskedOptIn(t *testing.T) { assertClientMask(t, true) }

func TestWSServer_AcceptsUnmaskedClient(t *testing.T) {
	_, fn, url := openServerBind(t, "")
	c := rawDial(t, url, "", false)
	if err := c.writeBinary([]byte("hello-unmasked")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := recvData(t, fn, 3*time.Second); !bytes.Equal(got, []byte("hello-unmasked")) {
		t.Errorf("delivered %q, want %q", got, "hello-unmasked")
	}
}

func TestWSServer_AcceptsMaskedClient(t *testing.T) {
	_, fn, url := openServerBind(t, "")
	c := rawDial(t, url, "", true)
	if err := c.writeBinary([]byte("hello-masked")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := recvData(t, fn, 3*time.Second); !bytes.Equal(got, []byte("hello-masked")) {
		t.Errorf("delivered %q, want %q", got, "hello-masked")
	}
}

func TestWSReadMessage_OversizeRejected(t *testing.T) {
	_, fn, url := openServerBind(t, "")
	c := rawDial(t, url, "", false)
	oversize := make([]byte, (1<<16)+1) // exceeds the wsReadLimit (1<<16) protocol guard
	if err := c.writeBinary(oversize); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := recvData(t, fn, 1*time.Second); got != nil {
		t.Errorf("oversize frame was delivered (%d bytes); want rejected before allocation", len(got))
	}
}

func TestWSReadMessage_FragmentAndControl(t *testing.T) {
	_, fn, url := openServerBind(t, "")
	c := rawDial(t, url, "", false)
	mustWrite := func(op ws.OpCode, fin bool, p string) {
		if err := ws.WriteFrame(c.conn, ws.NewFrame(op, fin, []byte(p))); err != nil {
			t.Fatalf("write frame: %v", err)
		}
	}
	// A binary message split across two frames with a ping interleaved between them.
	mustWrite(ws.OpBinary, false, "AB")
	mustWrite(ws.OpPing, true, "p")
	mustWrite(ws.OpContinuation, true, "CD")
	if got := recvData(t, fn, 3*time.Second); !bytes.Equal(got, []byte("ABCD")) {
		t.Fatalf("reassembled %q, want ABCD", got)
	}
	// A stray text message is discarded; the following binary message still delivers.
	mustWrite(ws.OpText, true, "ignored")
	mustWrite(ws.OpBinary, true, "EF")
	if got := recvData(t, fn, 3*time.Second); !bytes.Equal(got, []byte("EF")) {
		t.Errorf("after text discard delivered %q, want EF", got)
	}
}

func TestWSClient_PingPongBackstop(t *testing.T) {
	bridge := newWSBridge(t, false, true) // echo mode answers pings with pongs
	b := newClientBind(t)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	go drainReceiver(fns[0])
	ep := wsClientEndpoint(t, b, bridge.url(), 100*time.Millisecond)
	if err := b.Send([][]byte{{1}}, ep); err != nil { // opens the conn + starts pingLoop
		t.Fatalf("Send: %v", err)
	}
	prov, ok := any(b).(conn.WebSocketMetricsProvider)
	if !ok {
		t.Fatal("bind is not a metrics provider")
	}
	// The bridge pongs, so within a few intervals an RTT is recorded and no reconnect occurs.
	deadline := time.After(3 * time.Second)
	for {
		snap := prov.WSMetricsSnapshot()
		if snap.LastPingRTTSeconds > 0 {
			if snap.ReconnectsTotal != 0 {
				t.Errorf("healthy pong path caused %d reconnects, want 0", snap.ReconnectsTotal)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("no ping RTT recorded (pong not dispatched)")
		case <-time.After(50 * time.Millisecond):
		}
	}
}
