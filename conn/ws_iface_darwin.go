//go:build darwin

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"net/netip"
)

// egressIfIndexFn is a test seam (darwin-only); nil in production.
var egressIfIndexFn func() int

func (b *WebSocketBind) egressIfIndex() int {
	if egressIfIndexFn != nil {
		return egressIfIndexFn()
	}
	return defaultEgressIfIndex()
}

func wsIsIPv6(address string) bool {
	ap, err := netip.ParseAddrPort(address)
	return err == nil && ap.Addr().Is6() && !ap.Addr().Is4In6()
}

// wsIsLoopback reports whether the dial address is loopback; such dials never leave
// the host and must not be pinned to a physical egress interface.
func wsIsLoopback(address string) bool {
	ap, err := netip.ParseAddrPort(address)
	return err == nil && ap.Addr().IsLoopback()
}

// defaultEgressIfIndex returns the interface index of the default route
// (best-effort). Real on-device pinning is a Manual QA item.
func defaultEgressIfIndex() int {
	c, err := net.Dial("udp4", "8.8.8.8:53") // no packet is sent; selects the default-route source
	if err != nil {
		return 0
	}
	defer c.Close()
	la, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(la.IP) {
				return ifc.Index
			}
		}
	}
	return 0
}
