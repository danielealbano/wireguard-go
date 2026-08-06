//go:build linux || freebsd || openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"crypto/tls"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
)

// TestRawConnOf_UnwrapsTCPAndTLS verifies (privilege-free) that rawConnOf reaches the
// raw fd behind a *net.TCPConn directly and unwraps a *tls.Conn to the TCP conn.
func TestRawConnOf_UnwrapsTCPAndTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if _, err := rawConnOf(c); err != nil {
		t.Errorf("rawConnOf(*net.TCPConn): %v", err)
	}
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true}) // not handshaked; NetConn() unwrap only
	if _, err := rawConnOf(tc); err != nil {
		t.Errorf("rawConnOf(*tls.Conn): %v", err)
	}
}

// TestMarkConn_GracefulOnRealSocket exercises the markConn path on a real socket. It
// either succeeds (privileged) or returns a permission error (unprivileged CI); it
// must never panic. mark=0 keeps any side effect nil.
func TestMarkConn_GracefulOnRealSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = markConn(c, 0) // nil or a permission error; must not panic
}

// countRawConn is a syscall.RawConn whose Control records the invocation without
// touching a real fd, so a test can count how many live sockets SetMark visits
// without requiring CAP_NET_ADMIN. The real setsockopt is covered by
// TestMarkConn_GracefulOnRealSocket.
type countRawConn struct{ n *int32 }

func (r countRawConn) Control(func(uintptr)) error    { atomic.AddInt32(r.n, 1); return nil }
func (r countRawConn) Read(func(uintptr) bool) error  { return nil }
func (r countRawConn) Write(func(uintptr) bool) error { return nil }

// countConn is a net.Conn whose SyscallConn returns a counting RawConn.
type countConn struct {
	net.Conn
	n *int32
}

func (c countConn) SyscallConn() (syscall.RawConn, error) { return countRawConn{c.n}, nil }

// TestWebSocketBind_SetMark_RemarksLiveConns verifies that SetMark iterates over every
// currently-open socket — client dials AND server-accepted connections — re-marking
// each in place, which is the core of the full-tunnel fwmark fix.
func TestWebSocketBind_SetMark_RemarksLiveConns(t *testing.T) {
	var n int32
	mk := func() *wsConn { return &wsConn{conn: countConn{n: &n}} }
	b := &WebSocketBind{
		conns:  map[string]*wsClientConn{},
		sconns: map[uint64]*wsServerConn{},
	}
	b.conns["a"] = &wsClientConn{wc: mk(), ep: &WSEndpoint{wsURL: "wss://a/"}}
	b.conns["b"] = &wsClientConn{wc: mk(), ep: &WSEndpoint{wsURL: "wss://b/"}}
	b.sconns[1] = &wsServerConn{wc: mk(), id: 1}

	if err := b.SetMark(0x1234); err != nil {
		t.Fatalf("SetMark: %v", err)
	}
	if got := atomic.LoadInt32(&n); got != 3 {
		t.Errorf("SetMark re-marked %d live sockets, want 3 (2 client + 1 server)", got)
	}
	if b.mark.Load() != 0x1234 {
		t.Errorf("stored mark = %#x, want 0x1234", b.mark.Load())
	}
}

// TestWSDialControl_MarkAndProtectContract verifies the dial-time contract on a real
// socket, independent of privilege: the protect callback is invoked IFF the fwmark was
// applied successfully (dialControl returns nil). Under privilege the mark succeeds and
// protect runs; unprivileged the mark fails and protect is skipped. Either way the
// invariant holds and the path never panics.
func TestWSDialControl_MarkAndProtectContract(t *testing.T) {
	var protectCalls int32
	b := &WebSocketBind{cfg: wsConfig{protect: func(int) { atomic.AddInt32(&protectCalls, 1) }}}
	b.mark.Store(0x51820)

	dc := b.dialControl()
	if dc == nil {
		t.Fatal("dialControl returned nil with protect set")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rc, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	markErr := dc("tcp", ln.Addr().String(), rc)
	if (markErr == nil) != (atomic.LoadInt32(&protectCalls) == 1) {
		t.Errorf("mark/protect contract violated: markErr=%v protectCalls=%d", markErr, protectCalls)
	}
}
