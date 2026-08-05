# Configuration

This document covers the configuration surface **added by this fork** — the WebSocket / wstunnel
transport and the Prometheus metrics endpoint. Everything else (keys, peers, allowed IPs, the
`wg(8)` UAPI, `ip`/`ifconfig`) is unchanged from upstream wireguard-go.

The transport is selected **once at startup** by an environment variable; per-peer and per-listener
details are then set over the normal UAPI (`get=1`/`set=1`) control socket.

> **`wg(8)` compatibility:** stock `wg` / `wg-quick` reject a `wss://` endpoint and do not know the
> `ws_*` keys, so the WebSocket settings below are written **directly to the UAPI socket**
> (`/var/run/wireguard/<iface>.sock`). Standard fields (`private_key`, `public_key`, `allowed_ip`,
> `persistent_keepalive_interval`, …) are exactly as in `wg(8)`.

---

## 1. Transport selection

| Variable | Values | Meaning |
|---|---|---|
| `WG_TRANSPORT` | `udp` (default) · `ws` | `udp` is the stock UDP transport. `ws` selects the WebSocket transport. |
| `WG_WS_ROLE` | `client` (default) · `server` | WebSocket role when `WG_TRANSPORT=ws`. A **client** dials peer `endpoint` URLs; a **server** listens on `ws_listen`. |

## 2. Environment variables (WebSocket)

All are read once at startup; secrets are never logged.

| Variable | Applies to | Meaning |
|---|---|---|
| `WG_WS_MASK` | client | `1`/`true` ⇒ mask outgoing WebSocket frames. **Default off (unmasked)**, matching a default wstunnel server. When on, the peer **wstunnel server must run `--websocket-mask-frame`** (mask modes must match). |
| `WG_WS_TLS_CERT` / `WG_WS_TLS_KEY` | server | PEM cert + key files for the `wss://` listener. |
| `WG_WS_TLS_CA` | client | PEM CA file to trust the server certificate (empty ⇒ system roots). |
| `WG_WS_TLS_SERVERNAME` | client | Override the TLS SNI / verified name. |
| `WG_WS_TLS_INSECURE` | client | `1` ⇒ skip TLS verification (testing only). |
| `WG_WS_BEARER` | server | Expected pre-shared bearer token; the server rejects upgrades whose `Authorization: Bearer` does not match (constant-time). Empty ⇒ gate off. A coarse gate on top of the Noise handshake. |
| `WG_WS_PING_INTERVAL` | client | WebSocket keepalive/backstop interval (Go duration, e.g. `25s`). |
| `WG_WS_TRUSTED_PROXIES` | server | Comma-separated CIDRs from which `X-Forwarded-For` is trusted (server behind an HTTP reverse proxy). |

Stock env vars still apply: `LOG_LEVEL` (`debug`/`verbose`), `WG_TUN_NAME_FILE` (macOS/OpenBSD), and
`WG_METRICS_LISTEN` (see §5).

## 3. UAPI keys (WebSocket)

Additive keys accepted only when `WG_TRANSPORT=ws`. Every other unknown key is still rejected.

**Device-level** (set once, like `private_key`):

| Key | Role | Meaning |
|---|---|---|
| `ws_listen=<ws(s)://host:port/path>` | server | The listen URL for the WebSocket server. Setting it re-arms the listener (`BindUpdate`). |

`ws_listen` is a **persistent device scalar, like `listen_port`**: a `set=1` that omits it (e.g. a
full-replace `setconf`) leaves the current listener **unchanged** — it is not cleared by omission or by
`replace_peers`. To stop the server explicitly, send `ws_listen=` with an **empty** value, which cleanly
tears the listener down.

**Peer-level** (follow a `public_key` line, like `endpoint`/`allowed_ip`):

| Key | Meaning |
|---|---|
| `endpoint=<ws(s)://host:port[/path]>` | The peer's WebSocket URL (replaces the UDP `host:port` endpoint). |
| `ws_mode=standard\|wstunnel` | `standard` = this fork's native dialect (talks to a wireguard-go WS **server**). `wstunnel` = interop with a [wstunnel](https://github.com/erebe/wstunnel) server. Default `standard`. |
| `ws_target=<host:port>` | **wstunnel mode only** — the real WireGuard UDP endpoint the wstunnel server must forward to (the JWT `r`/`rp`). Required when `ws_mode=wstunnel`. |
| `ws_bearer=<token>` | Optional per-peer bearer: `standard` ⇒ `Authorization: Bearer <token>`; `wstunnel` ⇒ HTTP basic-auth (base64 `user:pass`). Never logged or echoed. |

## 4. Examples

Configure by writing a `set=1` block to the UAPI socket, e.g. `printf 'set=1\n…\n\n' | nc -U /var/run/wireguard/wg0.sock`. Keys are **hex**, as the UAPI requires.

**Native WebSocket — server** (`WG_TRANSPORT=ws WG_WS_ROLE=server WG_WS_TLS_CERT=… WG_WS_TLS_KEY=…`):

```
set=1
private_key=<hex>
ws_listen=wss://0.0.0.0:443/wg
public_key=<peer-hex>
allowed_ip=10.0.0.2/32
```

**Native WebSocket — client** (`WG_TRANSPORT=ws WG_WS_TLS_CA=/path/ca.pem`):

```
set=1
private_key=<hex>
public_key=<server-hex>
endpoint=wss://vpn.example.com:443/wg
allowed_ip=10.0.0.0/24
persistent_keepalive_interval=25
```

**wstunnel interop — client** (`WG_TRANSPORT=ws`), dialing a wstunnel server that forwards to a normal
UDP WireGuard endpoint. The default (empty) URL path targets wstunnel's default `/v1/events`:

```
set=1
private_key=<hex>
public_key=<server-hex>
endpoint=wss://vpn.example.com:8443
ws_mode=wstunnel
ws_target=127.0.0.1:51820
allowed_ip=10.0.0.0/24
persistent_keepalive_interval=25
```

## 5. Metrics (optional)

| Variable | Meaning |
|---|---|
| `WG_METRICS_LISTEN` | Address for a Prometheus `/metrics` HTTP listener (e.g. `127.0.0.1:9090`). Empty ⇒ metrics **off**. |

Exposes device/peer counters (handshakes, rx/tx, per-peer last-handshake) and, for the WebSocket
transport, connection/reconnect/RTT gauges. No key material is ever exported.

## 6. Notes

- **Masking:** the client is **unmasked by default** because a default wstunnel server does not unmask;
  turn on `WG_WS_MASK` only when the peer wstunnel server runs `--websocket-mask-frame`. This fork's own
  WebSocket **server accepts both** masked and unmasked client frames.
- **Roaming:** on a network change the transport reconnects (re-resolving DNS, re-pinning egress);
  the standalone daemon drives this from an OS path monitor, embedders via `device.BindUpdate()`.
- **Wire protocol is unchanged:** WebSocket only replaces the outer transport; the Noise handshake and
  WireGuard packet formats are identical, so a WS peer still authenticates with normal WireGuard keys.
