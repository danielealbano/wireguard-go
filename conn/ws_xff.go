/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net/http"
	"net/netip"
	"strings"
)

// resolveClientAddr returns the client's address for rate-limiter/MAC2 identity.
// If the direct peer is a configured trusted proxy, it walks X-Forwarded-For
// right-to-left past further trusted hops and returns the first untrusted hop;
// otherwise it returns the raw peer address and IGNORES any XFF (forgery-safe).
func resolveClientAddr(r *http.Request, trusted []netip.Prefix) netip.AddrPort {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.AddrPort{}
	}
	if len(trusted) == 0 || !prefixesContain(trusted, peer.Addr()) {
		return peer
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peer
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue
		}
		if prefixesContain(trusted, ip) {
			continue // another trusted proxy hop
		}
		return netip.AddrPortFrom(ip, 0)
	}
	return peer
}

func prefixesContain(ps []netip.Prefix, ip netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
