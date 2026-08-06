/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

type wsDialect int

const (
	wsDialectStandard wsDialect = iota
	wsDialectWstunnel
)

// WSEndpoint implements conn.Endpoint for the WebSocket transport. On the client
// (dialing) side it carries the resolved dial target plus the per-peer connection
// settings (ws_url, TLS material, mask, timings); on the server (inbound) side it
// carries the accepted client's address and the live-connection id used to
// dispatch Send. A client endpoint is distinguished by a non-empty wsURL.
type WSEndpoint struct {
	// client (outbound) — populated from the per-peer UAPI keys:
	wsURL          string         // ws_url: TLS scheme + SNI/Host + upgrade path
	dialTarget     netip.AddrPort // resolved endpoint= ip:port actually dialed
	dialect        wsDialect
	wstunnelTarget string // wstunnel mode: inner WG "host:port" (JWT r/rp)
	bearer         string // echoed by IpcGet for round-tripping, never logged
	mask           bool
	tlsCAPath      string
	tlsCertPath    string
	tlsKeyPath     string
	tlsInsecure    bool
	pingInterval   time.Duration
	backoffMin     time.Duration
	backoffMax     time.Duration

	// dial-config cache (endpoints are immutable after set):
	dcOnce sync.Once
	dc     *dialConfig
	dcErr  error

	// server (inbound):
	dst    netip.AddrPort // client remote (or XFF) addr
	connID uint64         // identifies the live accepted connection for Send dispatch
}

var _ Endpoint = (*WSEndpoint)(nil)

// key uniquely identifies a client (dialing) endpoint's connection in b.conns /
// b.dialBackoff, so two peers sharing a ws_url but different dial targets (or
// wstunnel targets) never collide on a single connection.
func (e *WSEndpoint) key() string {
	return e.wsURL + "|" + e.dialTarget.String() + "|" + e.wstunnelTarget
}

func (e *WSEndpoint) ClearSrc()           {}
func (e *WSEndpoint) SrcToString() string { return "" }
func (e *WSEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func (e *WSEndpoint) dstAddrPort() netip.AddrPort {
	if e.wsURL != "" {
		return e.dialTarget
	}
	return e.dst
}

func (e *WSEndpoint) DstIP() netip.Addr { return e.dstAddrPort().Addr() }

func (e *WSEndpoint) DstToBytes() []byte {
	b, _ := e.dstAddrPort().MarshalBinary() // stable per-peer key for MAC2 cookies
	return b
}

// DstToString reports the routable ip:port for a dialing endpoint — so
// `wg show endpoints` / wg-quick see a host-routable address exactly like UDP —
// and the accepted client's address for a server (inbound) endpoint.
func (e *WSEndpoint) DstToString() string { return e.dstAddrPort().String() }

// WSPeerKVs returns the additive get=1 key=value lines for a dialing endpoint,
// omitting empty/zero values, in a stable order. Durations are emitted as integer
// milliseconds. The bearer is echoed (like preshared_key) but MUST never be logged.
func (e *WSEndpoint) WSPeerKVs() []string {
	if e.wsURL == "" {
		return nil // inbound/server endpoint carries no configured client settings
	}
	kv := []string{"ws_url=" + e.wsURL}
	if e.wstunnelTarget != "" {
		kv = append(kv, "wstunnel_target="+e.wstunnelTarget)
	}
	if e.bearer != "" {
		kv = append(kv, "ws_bearer="+e.bearer)
	}
	if e.mask {
		kv = append(kv, "ws_mask=true")
	}
	if e.tlsCAPath != "" {
		kv = append(kv, "ws_tls_ca="+e.tlsCAPath)
	}
	if e.tlsCertPath != "" {
		kv = append(kv, "ws_tls_cert="+e.tlsCertPath)
	}
	if e.tlsKeyPath != "" {
		kv = append(kv, "ws_tls_key="+e.tlsKeyPath)
	}
	if e.tlsInsecure {
		kv = append(kv, "ws_tls_insecure=true")
	}
	if e.pingInterval > 0 {
		kv = append(kv, fmt.Sprintf("ws_ping_interval=%d", e.pingInterval/time.Millisecond))
	}
	if e.backoffMin > 0 {
		kv = append(kv, fmt.Sprintf("ws_backoff_min=%d", e.backoffMin/time.Millisecond))
	}
	if e.backoffMax > 0 {
		kv = append(kv, fmt.Sprintf("ws_backoff_max=%d", e.backoffMax/time.Millisecond))
	}
	return kv
}
