/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// waitAccepted fails the test unless the stalled server accepts a connection in time,
// i.e. unless a dial to it is actually in flight.
func waitAccepted(t *testing.T, accepted <-chan struct{}) {
	t.Helper()
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("no dial reached the stalled server")
	}
}

func TestWSClient_SendDoesNotBlockOnStalledDial(t *testing.T) {
	url, accepted := newWSStalledServer(t)
	b := newClientBind(t)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	ep := wsClientEndpoint(t, b, url, 0)

	start := time.Now()
	err := b.Send([][]byte{{1}}, ep)
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("Send blocked for %v on a stalled dial", elapsed)
	}
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	waitAccepted(t, accepted)

	start = time.Now()
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Close blocked for %v on an in-flight dial", elapsed)
	}
}

func TestWSClient_QueuedPacketsWrittenInOrder(t *testing.T) {
	url, got := newWSDelayedRecorder(t, 200*time.Millisecond)
	b := newClientBind(t)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	go drainReceiver(fns[0])
	ep := wsClientEndpoint(t, b, url, 0)

	const n = 5
	for i := 1; i <= n; i++ {
		if err := b.Send([][]byte{{byte(i)}}, ep); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	for i := 1; i <= n; i++ {
		select {
		case msg := <-got:
			if !bytes.Equal(msg, []byte{byte(i)}) {
				t.Fatalf("packet %d: got %v, want [%d]", i, msg, i)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("packet %d was not delivered", i)
		}
	}
}

func TestWSClient_StalledDialDoesNotDelayOtherEndpoint(t *testing.T) {
	stalled, accepted := newWSStalledServer(t)
	bridge := newWSBridge(t, false, true) // echo mode
	b := newClientBind(t)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if err := b.Send([][]byte{{1}}, wsClientEndpoint(t, b, stalled, 0)); err != nil {
		t.Fatalf("Send to the stalled endpoint: %v", err)
	}
	waitAccepted(t, accepted)
	if err := b.Send([][]byte{{2}}, wsClientEndpoint(t, b, bridge.url(), 0)); err != nil {
		t.Fatalf("Send to the healthy endpoint: %v", err)
	}

	type result struct {
		payload []byte
		err     error
	}
	res := make(chan result, 1)
	go func() {
		bufs := [][]byte{make([]byte, 64)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		n, err := fns[0](bufs, sizes, eps)
		if err == nil && n != 1 {
			err = fmt.Errorf("received %d packets, want 1", n)
		}
		res <- result{payload: bufs[0][:sizes[0]], err: err}
	}()
	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("receive: %v", r.err)
		}
		if !bytes.Equal(r.payload, []byte{2}) {
			t.Fatalf("echo: got %v, want [2]", r.payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the healthy endpoint was held up by the stalled dial")
	}
}

func TestWSClient_SendOnUnopenedBind(t *testing.T) {
	b := newClientBind(t)
	ep := wsClientEndpoint(t, b, "ws://127.0.0.1:1/x", 0)
	if err := b.Send([][]byte{{1}}, ep); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send on a never-opened bind: got %v, want net.ErrClosed", err)
	}
}

// TestWSDevice_BindUpdateNotBlockedByStalledDial is the regression test for the
// device-level hang: the device sends while holding its network lock, so a dial made
// inside Send used to block BindUpdate (and Close) until the dial ended.
func TestWSDevice_BindUpdateNotBlockedByStalledDial(t *testing.T) {
	url, accepted := newWSStalledServer(t)
	priv, _ := wgKeypair(t)
	_, peerPub := wgKeypair(t)
	tdev := tuntest.NewChannelTUN()
	wsb, err := conn.NewWebSocketBind(conn.WithWSLogger(conn.Logger{}))
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	d := device.NewDevice(tdev.TUN(), wsb, device.NewLogger(device.LogLevelError, ""))
	cfg := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\ntransport=websocket\nendpoint=%s\nws_url=%s\npersistent_keepalive_interval=1\nallowed_ip=1.0.0.2/32\n",
		priv, peerPub, wsURLHost(t, url), url,
	)
	if err := d.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	if err := d.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	waitAccepted(t, accepted) // the handshake initiation's dial is now in flight

	updated := make(chan error, 1)
	go func() { updated <- d.BindUpdate() }()
	select {
	case err := <-updated:
		if err != nil {
			t.Fatalf("BindUpdate: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("BindUpdate blocked behind a stalled WebSocket dial")
	}

	closed := make(chan struct{})
	go func() {
		d.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked behind a stalled WebSocket dial")
	}
}
