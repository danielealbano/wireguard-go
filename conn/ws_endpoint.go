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
	url            string         // client: canonical ws(s):// URL, echoed by IpcGet
	dialect        wsDialect      // client only
	wstunnelTarget string         // client, wstunnel mode: real WireGuard "host:port" (JWT r/rp)
	bearer         string         // client: optional bearer; echoed by IpcGet for round-tripping (like preshared_key), never logged
	dst            netip.AddrPort // server: client remote (or XFF) addr; client: advisory (zero)
	connID         uint64         // server: identifies the live connection for Send dispatch
}

var _ Endpoint = (*WSEndpoint)(nil)

// WSConfig reports this endpoint's additive UAPI settings (ws_mode/wstunnel_target/ws_bearer)
// so IpcGet can round-trip them. ok is false for server inbound endpoints (they carry no
// configured URL), so IpcGet emits the ws_* keys only for client, URL-configured peers.
func (e *WSEndpoint) WSConfig() (mode, wstunnelTarget, bearer string, ok bool) {
	if e.url == "" {
		return "", "", "", false
	}
	mode = "standard"
	if e.dialect == wsDialectWstunnel {
		mode = "wstunnel"
	}
	return mode, e.wstunnelTarget, e.bearer, true
}

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
