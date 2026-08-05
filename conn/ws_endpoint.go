/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "net/netip"

type wsDialect int

const (
	wsDialectStandard wsDialect = iota
	wsDialectWstunnel
)

// WSEndpoint implements conn.Endpoint for the WebSocket transport. On the client
// it carries the canonical dial URL and dialect fields; on the server it carries
// the accepted client's address and the live-connection id used to dispatch Send.
type WSEndpoint struct {
	url     string         // client: canonical ws(s):// URL, echoed by IpcGet
	dialect wsDialect      // client only
	target  string         // client, wstunnel mode: real WireGuard "host:port" (JWT r/rp)
	bearer  string         // client: optional bearer; NEVER echoed or logged
	dst     netip.AddrPort // server: client remote (or XFF) addr; client: advisory (zero)
	connID  uint64         // server: identifies the live connection for Send dispatch
}

var _ Endpoint = (*WSEndpoint)(nil)

func (e *WSEndpoint) ClearSrc()           {}
func (e *WSEndpoint) SrcToString() string { return "" }
func (e *WSEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *WSEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }

func (e *WSEndpoint) DstToBytes() []byte {
	b, _ := e.dst.MarshalBinary() // stable per-client key for MAC2 cookies
	return b
}

func (e *WSEndpoint) DstToString() string {
	if e.url != "" {
		return e.url
	}
	return e.dst.String()
}
