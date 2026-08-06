//go:build darwin

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"sync/atomic"
	"testing"
)

// fakeRawConn is a syscall.RawConn whose Control invokes f with an arbitrary fd.
// darwin dialControl only calls the protect callback (no marking/pinning), so no
// real socket option is set.
type fakeRawConn struct{}

func (fakeRawConn) Control(f func(uintptr)) error { f(3); return nil }
func (fakeRawConn) Read(func(uintptr) bool) error { return nil }
func (fakeRawConn) Write(func(uintptr) bool) error { return nil }

func TestWSPinning_ProtectInvoked(t *testing.T) {
	var calls atomic.Int64
	b := &WebSocketBind{cfg: wsConfig{protect: func(int) { calls.Add(1) }}}
	dc := b.dialControl()
	if dc == nil {
		t.Fatal("dialControl nil with protect set")
	}
	if err := dc("tcp", "1.2.3.4:443", fakeRawConn{}); err != nil {
		t.Fatalf("dialControl: %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("protect called %d times, want 1", calls.Load())
	}
}

func TestWSPinning_NoProtect_NoControl(t *testing.T) {
	b := &WebSocketBind{}
	if b.dialControl() != nil {
		t.Error("darwin dialControl should be nil when protect is unset (no pinning)")
	}
}
