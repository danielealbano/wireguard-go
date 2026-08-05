//go:build darwin

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"sync"
	"testing"
)

// fakeRawConn is a syscall.RawConn stand-in whose Control invokes the callback with
// a dummy fd, so the dialControl hook can be exercised without a real socket.
type fakeRawConn struct{ mu sync.Mutex }

func (c *fakeRawConn) Control(f func(uintptr)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(0)
	return nil
}
func (c *fakeRawConn) Read(func(uintptr) bool) error  { return nil }
func (c *fakeRawConn) Write(func(uintptr) bool) error { return nil }

func TestWSPinning_RecomputesOnRedial(t *testing.T) {
	var calls int
	egressIfIndexFn = func() int { calls++; return 0 } // 0 => skip the IP_BOUND_IF syscall
	t.Cleanup(func() { egressIfIndexFn = nil })

	b := &WebSocketBind{}
	ctrl := b.dialControl()
	if ctrl == nil {
		t.Fatal("dialControl returned nil")
	}
	for i := 0; i < 2; i++ {
		if err := ctrl("tcp4", "203.0.113.1:443", &fakeRawConn{}); err != nil {
			t.Fatalf("dial %d control: %v", i, err)
		}
	}
	if calls != 2 {
		t.Errorf("egress interface detection ran %d times, want 2 (recomputed per dial)", calls)
	}
}

func TestWSPinning_ProtectInvoked(t *testing.T) {
	egressIfIndexFn = func() int { return 0 }
	t.Cleanup(func() { egressIfIndexFn = nil })

	var protects int
	b := &WebSocketBind{}
	b.cfg.protect = func(fd int) { protects++ }
	ctrl := b.dialControl()
	if err := ctrl("tcp4", "203.0.113.1:443", &fakeRawConn{}); err != nil {
		t.Fatalf("control: %v", err)
	}
	if protects != 1 {
		t.Errorf("protect callback invoked %d times, want 1 per dial", protects)
	}
}
