# Configuration

This fork configures the transport **per peer**, entirely through the UAPI (`get=1`/`set=1`)
control socket. There are **no `WG_WS_*` environment variables** and no config file — the modified
`wireguard-tools`/`wireguard-android` emit the keys below. The wire protocol is unchanged: a
WebSocket/wstunnel peer speaks the exact same WireGuard packets as a UDP peer, only the carrier
differs, so a `wstunnel` peer can reach a stock UDP WireGuard server.

## 1. Per-peer transport (mandatory)

Every peer declares a carrier with a **mandatory** `transport` key at creation:

| `transport` | Carrier |
|---|---|
| `udp` | Plain UDP (stock WireGuard). |
| `websocket` | WireGuard over a WebSocket (ws/wss). |
| `wstunnel` | WireGuard over a [wstunnel](https://github.com/erebe/wstunnel) relay. |

Creating a peer without `transport=` is rejected. An incremental `set` that updates an existing peer
may omit it and keeps the persisted value. `transport=` is round-tripped by `get=1`.

## 2. `endpoint` and `ws_url`

`endpoint=` is a **plain, resolved `ip:port`** for every transport — the address packets go to — so
`wg-quick` host-routes it and Linux `fwmark` marks the socket, exactly like UDP.

For `websocket`/`wstunnel` peers the WebSocket/TLS/HTTP layer is carried by a separate per-peer
`ws_url` (`ws(s)://host:port/path`): the scheme selects TLS, the host is the TLS SNI + HTTP `Host`
header + cert name, and the path is the WS upgrade path. wireguard-go dials the exact `endpoint`
`ip:port` using `ws_url` only for the TLS/HTTP layer, so there is no DNS-resolution race.

A `websocket`/`wstunnel` peer with **no `ws_url`** is an **inbound** peer: it does not dial; its
endpoint is learned when it connects to this device's `ws_listen` (the `ws_url`↔`endpoint` analogy of
a UDP peer with no `endpoint`).

## 3. Per-peer UAPI keys (client / dialing side)

All are per-peer, optional (except as noted), and round-tripped by `get=1`:

| Key | Meaning |
|---|---|
| `ws_url` | `ws(s)://host:port/path` — TLS scheme + SNI/Host + upgrade path. Required to dial. |
| `wstunnel_target` | `host:port` of the inner WireGuard endpoint the wstunnel relay forwards to. Required for `transport=wstunnel` (dialing); rejected otherwise. |
| `ws_bearer` | Bearer token sent to the server (`Authorization: Bearer …`). Echoed by `get=1`, NEVER logged. |
| `ws_mask` | `true` to mask client frames (needs a wstunnel server run with `--websocket-mask-frame`). Default unmasked. |
| `ws_tls_ca` | Path to a PEM CA bundle used to verify the server (wss). |
| `ws_tls_cert` / `ws_tls_key` | Paths to a client cert/key for mutual TLS (wss). |
| `ws_tls_insecure` | `true` to skip server-cert verification (wss). |
| `ws_ping_interval` / `ws_backoff_min` / `ws_backoff_max` | Keepalive ping interval and reconnect backoff, in **milliseconds** (0 ⇒ defaults). |

`ws_*` keys are rejected for `transport=udp`.

## 4. Device-level UAPI keys (server / listener side)

| Key | Meaning |
|---|---|
| `ws_listen` | `ws(s)://host:port/path` the device listens on (the `listen_port` analogue). Persistent, like `listen_port`. |
| `ws_server_tls_cert` / `ws_server_tls_key` | Paths to the server's TLS cert/key (wss listener). |
| `ws_server_bearer` | Expected `Authorization: Bearer` value; empty ⇒ gate off. NEVER logged. |
| `ws_trusted_proxies` | Comma-separated CIDRs whose `X-Forwarded-For` is trusted for the client's source address. |

A device is a WS **server** whenever `ws_listen` is set and a WS **client** toward any peer with a
`ws_url` — both at once. These require the WebSocket transport (present in the daemon by default).

## 5. Examples (UAPI `set=1` bodies)

Plain UDP peer:

```
transport=udp
endpoint=203.0.113.5:51820
allowed_ip=10.10.0.0/24
```

Standard WebSocket (wss) client peer:

```
transport=websocket
endpoint=203.0.113.5:8443
ws_url=wss://vpn.example.com:8443/wg
ws_tls_ca=/etc/wireguard/ca.pem
allowed_ip=0.0.0.0/0
```

wstunnel client peer:

```
transport=wstunnel
endpoint=203.0.113.5:8443
ws_url=wss://vpn.example.com:8443/v1
wstunnel_target=127.0.0.1:51820
allowed_ip=0.0.0.0/0
```

Device acting as a WS server (device lines + one inbound peer):

```
ws_listen=wss://0.0.0.0:8443/wg
ws_server_tls_cert=/etc/wireguard/server-cert.pem
ws_server_tls_key=/etc/wireguard/server-key.pem
public_key=<peer pubkey>
transport=websocket
allowed_ip=10.10.0.2/32
```

## 6. Metrics (optional)

An operational Prometheus listener is still controlled by the `WG_METRICS_LISTEN` environment
variable (host:port). This is the only remaining WebSocket-related environment variable.

## 7. Notes

- Full-tunnel (`AllowedIPs=0.0.0.0/0`) is `wg-quick`'s job — see `docs/WGQUICK_INTEGRATION.md`.
- Secrets (`ws_bearer`, `ws_server_bearer`, key material) are round-tripped by `get=1` over the
  trusted control socket but are NEVER written to logs.
- TLS material is passed as file paths; the paths must be readable by the daemon.
