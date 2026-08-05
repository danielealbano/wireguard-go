/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func TestWSClient_Handshake_WS(t *testing.T) {
	a, b, _ := newWSDevicePair(t, false)
	wsAssertPing(t, a, b, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 2}, 10*time.Second)
	wsAssertPing(t, b, a, [4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 1}, 10*time.Second)
}

func TestWSClient_Handshake_WSS(t *testing.T) {
	a, b, _ := newWSDevicePair(t, true)
	wsAssertPing(t, a, b, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 2}, 10*time.Second)
}

func TestWSClient_ServerDropReconnect(t *testing.T) {
	a, b, bridge := newWSDevicePair(t, false)
	wsAssertPing(t, a, b, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 2}, 10*time.Second)
	// Force both live connections closed; the read loops must detect the drop and
	// the next Send must re-dial and re-pair through the relay so traffic resumes.
	bridge.dropAll()
	wsAssertPing(t, a, b, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 2}, 15*time.Second)
	wsAssertPing(t, b, a, [4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 1}, 15*time.Second)
}

func TestWSClient_ConcurrentSenders(t *testing.T) {
	bridge := newWSBridge(t, false, true) // echo
	b := newClientBind(t)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	for _, fn := range fns {
		go func(fn conn.ReceiveFunc) {
			for {
				bufs := [][]byte{make([]byte, 2048)}
				if _, err := fn(bufs, make([]int, 1), make([]conn.Endpoint, 1)); err != nil {
					return
				}
			}
		}(fn)
	}
	ep, err := b.ParseEndpoint(bridge.url())
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if err := b.Send([][]byte{{byte(i), byte(j)}}, ep); err != nil {
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestWSClient_ProtectInvokedOnDial(t *testing.T) {
	bridge := newWSBridge(t, false, true)
	var protects atomic.Int64
	b, err := conn.NewWebSocketBind(
		conn.WithWSRole(conn.WSRoleClient),
		conn.WithWSProtect(func(fd int) { protects.Add(1) }),
	)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	go func() {
		for {
			if _, err := fns[0]([][]byte{make([]byte, 2048)}, make([]int, 1), make([]conn.Endpoint, 1)); err != nil {
				return
			}
		}
	}()
	ep, _ := b.ParseEndpoint(bridge.url())
	if err := b.Send([][]byte{{1, 2, 3}}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if protects.Load() < 1 {
		t.Errorf("protect callback not invoked on dial (got %d)", protects.Load())
	}
}

func TestWSClient_BackoffBounded(t *testing.T) {
	b := newClientBind(t)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	// Port 1 is refused; the first Send fails and arms the backoff.
	ep, _ := b.ParseEndpoint("ws://127.0.0.1:1/x")
	if err := b.Send([][]byte{{1}}, ep); err == nil {
		t.Fatal("expected dial error to a refused port")
	}
	// While backing off, a subsequent Send returns quickly with a backoff error
	// instead of attempting another (up to 15s) dial.
	start := time.Now()
	err := b.Send([][]byte{{1}}, ep)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "backoff") {
		t.Fatalf("expected backoff error, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("backoff did not short-circuit the dial (took %v)", elapsed)
	}
}

func TestWSClient_PingTimeoutReconnect(t *testing.T) {
	url := newWSSilentServer(t)
	b, err := conn.NewWebSocketBind(
		conn.WithWSRole(conn.WSRoleClient),
		conn.WithWSPingInterval(150*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	prov, ok := any(b).(conn.WebSocketMetricsProvider)
	if !ok {
		t.Fatal("bind is not a metrics provider")
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	ep, _ := b.ParseEndpoint(url)
	if err := b.Send([][]byte{{1}}, ep); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// The silent server never pongs, so the ping backstop must tear the connection
	// down within a few ping intervals, recorded as a reconnect.
	deadline := time.After(5 * time.Second)
	for {
		if prov.WSMetricsSnapshot().ReconnectsTotal >= 1 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("ping timeout did not trigger a reconnect")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestWSClient_BindUpdateCycleNoLeak(t *testing.T) {
	b := newClientBind(t)
	baseline := runtime.NumGoroutine()
	for i := 0; i < 5; i++ {
		fns, _, err := b.Open(0)
		if err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
		if len(fns) == 0 {
			t.Fatalf("Open %d: no receive funcs", i)
		}
		if err := b.Close(); err != nil {
			t.Fatalf("Close %d: %v", i, err)
		}
	}
	settled := false
	for i := 0; i < 50; i++ {
		if runtime.NumGoroutine() <= baseline+2 {
			settled = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !settled {
		t.Errorf("goroutine leak: baseline=%d now=%d", baseline, runtime.NumGoroutine())
	}
}
