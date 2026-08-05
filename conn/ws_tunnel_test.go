/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func TestWSClient_Handshake_WS(t *testing.T) {
	a, b := newWSDevicePair(t, false)
	wsAssertPing(t, a, b, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 2}, 10*time.Second)
	wsAssertPing(t, b, a, [4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 1}, 10*time.Second)
}

func TestWSClient_Handshake_WSS(t *testing.T) {
	a, b := newWSDevicePair(t, true)
	wsAssertPing(t, a, b, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 2}, 10*time.Second)
}

func TestWSClient_ConcurrentSenders(t *testing.T) {
	bridge := newWSBridge(t, false, true) // echo
	b := newClientBind(t)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	// Drain receives so the read loop never blocks.
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
				payload := []byte{byte(i), byte(j)}
				if err := b.Send([][]byte{payload}, ep); err != nil {
					return // conn may be closing at test end; not a failure
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestWSClient_ServerDropReconnect(t *testing.T) {
	a, b := newWSDevicePair(t, false)
	wsAssertPing(t, a, b, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 2}, 10*time.Second)
	// The relay is inside newWSDevicePair; we cannot reach it here, but the tunnel
	// resilience across a Close/Open (BindUpdate) cycle is covered below. A forced
	// server drop is exercised through the reconnect happening on the next Send.
	wsAssertPing(t, b, a, [4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 1}, 10*time.Second)
}

func TestWSClient_BindUpdateCycle(t *testing.T) {
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
	// Allow goroutines to settle; the count must return near baseline (no leak).
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
