//go:build linux || freebsd || openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"crypto/tls"
	"net"
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
