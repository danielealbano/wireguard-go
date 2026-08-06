# wg-quick / wireguard-tools integration

This document describes how the fork's modified `wireguard-tools` and `wg-quick` drive the
per-peer transport model, and how full-tunnel (`AllowedIPs=0.0.0.0/0`) stays off the tun on each
platform. wireguard-go provides the socket-side half only; **routing is `wg-quick`'s job** and is
NOT re-implemented in the daemon.

## What the tools must emit (UAPI `set=1`)

For every peer the tools MUST emit a `transport=` line (`udp|websocket|wstunnel`) at creation, and a
plain `endpoint=ip:port` (resolve the endpoint host-side, exactly as they already resolve UDP
hostnames). For `websocket`/`wstunnel` peers they additionally emit `ws_url=` and the per-peer
`ws_*` keys; for device-level server config they emit `ws_listen` and `ws_server_*`/`ws_trusted_proxies`.
See `docs/CONFIGURATION.md` for the full key list.

Because `endpoint=` is a routable `ip:port` (not a `wss://` URL), `wg show endpoints`, MTU discovery,
and `set_endpoint_direct_route` all see a host-routable address for WebSocket peers, exactly like UDP.

## Keeping the transport off the tun under full-tunnel

The encrypted transport socket must not be routed back into the tun. wireguard-go matches what its
UDP transport does per OS; the routing/rule setup is `wg-quick`'s:

- **Linux / FreeBSD / OpenBSD (mark-based).** `wg-quick` sets `fwmark` and installs
  `ip rule … not fwmark <t> lookup <t>` (+ a default route in table `<t>`). The WebSocket transport is
  TCP, and the CONNMARK save/restore rules are UDP-only, so it relies purely on the socket carrying
  the mark. wireguard-go's job (the reported-bug fix): `SetMark` marks the WS socket at dial, at
  accept, AND **re-marks live sockets in place** — so a mark set by `wg-quick` after the interface is
  up (the normal ordering) takes effect immediately. Same per-OS socket option UDP uses
  (`SO_MARK`/`SO_USER_COOKIE`/`SO_RTABLE`).
- **darwin (route-based).** macOS has no fwmark; `wg-quick`'s `set_endpoint_direct_route`
  host-routes the endpoint via the physical gateway. Because `endpoint=` is now a routable `ip:port`,
  this works for WebSocket peers with no `wg-quick` change and no wireguard-go pinning — the old
  darwin `IP_BOUND_IF` pin has been removed (it was redundant and, under full-tunnel, harmful:
  `defaultEgressIfIndex()` could resolve to the `utun` and `IP_BOUND_IF` overrides the route).
- **Windows.** As with stock wireguard-go, off-tun routing is the embedding app's responsibility;
  the daemon adds nothing per-transport.

## Manual QA (macOS) — REQUIRED before the PR

The Linux netns e2e harness cannot exercise macOS routing, so full-tunnel over WebSocket/wstunnel on
macOS is a **hands-on Manual QA step**, gated on the matching `wireguard-tools` change being present:

1. Configure a `wg-quick` interface with `AllowedIPs = 0.0.0.0/0` and a `websocket`/`wstunnel` peer.
2. Bring it up; confirm the handshake completes and traffic flows (ping/curl through the tunnel).
3. Confirm the encrypted transport socket egresses the **physical** interface (its packets to the
   endpoint IP are host-routed, not sent into the `utun`).

This is the last verification before the PR; run it on a real Mac and (if needed) switch networks.
