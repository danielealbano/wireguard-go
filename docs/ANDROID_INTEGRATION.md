# Android Integration — WebSocket Backend Swap

Companion to `docs/WORK_PLAN.md` (phase **P9**). It records exactly how the official WireGuard Android
app embeds this Go library today, and the concrete changes required to run the **WebSocket transport**
inside it — i.e. to "swap the Go backend" for a build that speaks `ws(s)://`.

All facts below are verified against the checkouts on disk:
- **this repo** — `golang.zx2c4.com/wireguard` (wireguard-go), paths linked.
- **the app** — `../wireguard-android` (sibling checkout), paths given as plain text (outside this workspace).

The changes span **three layers**. Only Layer A is in this repository; Layers B and C are the user's
forks of wireguard-android and are listed so the interface this repo must expose is unambiguous.

---

## 1. How it works today (verified)

The app builds this library as a C-shared object (`libwg-go`) with a tiny JNI shim, and drives it over
a UAPI settings string.

```mermaid
flowchart TD
    subgraph AppJava["App (Java) — wireguard-android"]
        GB["GoBackend.setStateInternal\nbuilds VpnService tun + config"]
        PROT["service.protect(fd)"]
    end
    subgraph Shim["JNI shim — libwg-go"]
        JNI["jni.c\nJava_...GoBackend_wgTurnOn"]
        API["api-android.go\nwgTurnOn / wgGetSocketV4/V6"]
    end
    subgraph GoLib["wireguard-go (this repo)"]
        DEV["device.NewDevice(tun, bind, logger)"]
        BIND["conn.NewStdNetBind() (UDP)"]
        PEEK["conn.PeekLookAtSocketFd4/6"]
    end

    GB -- "wgTurnOn(name, tunFd, goConfig)" --> JNI --> API --> DEV
    API -- "hardcoded" --> BIND
    DEV --> BIND
    GB -- "wgGetSocketV4/V6(handle)" --> API --> PEEK --> BIND
    GB --> PROT
    PROT -. "protects the ONE UDP fd, once" .-> BIND
```

Key facts:
- **Config path is a single UAPI/userspace string.** Java builds `config.toWgUserspaceString()`
  (`GoBackend.java:294`) and passes it to `wgTurnOn(name, tun.detachFd(), goConfig)`
  (`GoBackend.java:341`); the Go side applies it via `device.IpcSet(settings)`
  (`api-android.go:93`). There are **no env vars or CLI flags** on Android.
- **The bind is hardcoded to UDP.** `device.NewDevice(tun, conn.NewStdNetBind(), logger)`
  (`api-android.go:91`).
- **Socket protection is one-shot, one fd per family.** Java calls
  `service.protect(wgGetSocketV4(handle))` and `…V6` once after turn-on
  (`GoBackend.java:349-350`); those exports return the single UDP socket via
  `bind.PeekLookAtSocketFd4/6()` (`api-android.go:172,189`), which requires the bind to implement
  [`conn.PeekLookAtSocketFd`](../conn/conn.go#L69) (one fd per family).
- **Mobile roaming is pinned.** `DisableSomeRoamingForBrokenMobileSemantics()` (`api-android.go:99`).
- **Endpoints are pre-resolved to IPs** in Java before building the config
  (`GoBackend.java:278`, `InetEndpoint`), and `InetEndpoint.parse` accepts only `host:port`.
- **JNI shim** exports exactly `wgTurnOn/wgTurnOff/wgGetSocketV4/wgGetSocketV6/wgGetConfig/wgVersion`
  (`jni.c`); there is **no** callback/protect-callback infrastructure.

---

## 2. What WebSocket changes — the two cruxes

1. **Per-connection socket protection.** UDP has one fixed socket, protected once. WebSocket is TCP:
   connections are **dialed, dropped, and re-dialed** (every network switch = a new socket). The
   one-shot `wgGetSocketV4/V6` model cannot protect sockets that come and go. Each WS socket must be
   `VpnService.protect()`-ed **at dial time**, so the Go bind must **call back into Java per dial**.
   This is the Android delivery of the same egress-loop prevention that `IP_BOUND_IF`/`SO_MARK`
   provide on desktop (`docs/WORK_PLAN.md` D11) — but on an unprivileged app, `protect()` is the only
   sanctioned mechanism, hence a callback rather than `SO_MARK`.

2. **All WS config must travel in the UAPI settings string.** Because Android passes only the
   `toWgUserspaceString()` blob and no flags/env, the transport selection, `ws_mode`, `ws_target`,
   `ws_bearer`, and any TLS options must be expressible as **UAPI keys** (the "embedder-supplied on
   mobile" branch of `docs/WORK_PLAN.md` D17) or as new `wgTurnOn` parameters. On desktop these live
   at process level; on Android they cannot.

---

## 3. Changes by layer

### Layer A — wireguard-go (THIS repo; delivered by `docs/WORK_PLAN.md`)

- **WS bind constructible programmatically.** Android never runs `main.go`; it calls
  `device.NewDevice(tun, bind, logger)` directly. The WS bind must be creatable the same way, e.g.
  `conn.NewWebSocketBind(cfg)` (WORK_PLAN P1/P2/P6).
- **Per-dial protect hook — the one new interface.** The WS client bind MUST accept a protect
  callback `func(fd int)` (functional option) and invoke it inside `net.Dialer.Control` for **every**
  dialed socket, before use. This is the sole new cross-language contract Android needs.
- **WS config via UAPI.** The additive keys (`ws_listen`, URL `endpoint`, `ws_mode`, `ws_target`,
  `ws_bearer`, plus any TLS/servername/CA needed by a mobile client) must parse from the settings
  string in `device/uapi.go` (WORK_PLAN P1), since that is the only channel Android has.
- **The WS bind MUST NOT implement `conn.PeekLookAtSocketFd`.** With no single persistent socket,
  `wgGetSocketV4/V6` should simply return `-1` (harmless); protection goes through the per-dial hook.
- **URL endpoints, resolved at dial time** (WORK_PLAN P2/P4) — not pre-resolved to an IP.
- **Network-switch bump: nothing new needed.** `device.BindUpdate()` is already exported; the WS
  bind's `Close`/`Open` implement full teardown/re-arm so a bump = reconnect + re-pin + DNS
  re-resolve (WORK_PLAN D10/D19/P4). In-process netlink is NOT an option on Android: apps targeting
  API 30+ can't `bind()` `NETLINK_ROUTE` sockets nor send `RTM_GETLINK`
  (developer.android.com/training/articles/user-data-ids), so the signal must come from the app.
- **TLS: system roots only** (decided) — no TLS material crosses UAPI (WORK_PLAN §4, TLS row).

### Layer B — libwg-go (`../wireguard-android/tunnel/tools/libwg-go`; user's fork)

- **Depend on the WS-capable fork.** Point `go.mod` at the user's wireguard-go fork.
- **Select the bind by config.** In `wgTurnOn` (`api-android.go:76`), replace the hardcoded
  `conn.NewStdNetBind()` (`api-android.go:91`) with logic that picks the WS bind when the config
  indicates the WS transport (parse it from `settings`, or add a `wgTurnOn` parameter). Construct the
  WS bind wired to the protect callback below.
- **Add the protect-callback bridge (Go → Java).** A new export (e.g. `wgSetProtectCallback`, or an
  extra `wgTurnOn` argument) that stores the JVM handle + a Java method reference; the Go protect hook
  calls a C function in `jni.c` that does `AttachCurrentThread` and invokes
  `VpnService.protect(fd)` (see §4). Add the declaration to `jni.c` alongside the existing exports.
- **Add a network-switch bump export.** A `wgBumpSockets`-style export wrapping the already-exported
  `device.BindUpdate()` (mirrors `api-apple.go:176-188` in wireguard-apple), called from the app's
  `ConnectivityManager.NetworkCallback` (WORK_PLAN D19).

### Layer C — app (`../wireguard-android`, Java; user's fork)

- **`InetEndpoint.parse`** — accept `ws(s)://host:port/path` URLs (the user has already committed to
  this).
- **Config model** — `Config`/`Peer`/`Interface` and `toWgUserspaceString()` must carry and emit the
  WS keys so they reach `wgTurnOn`'s settings (`GoBackend.java:294`).
- **Do not pre-resolve WS endpoints.** Bypass the `InetEndpoint` DNS pre-resolution
  (`GoBackend.java:278`) for WS URLs — DNS is resolved in the bind at dial time (needed for reconnect).
- **Register the protect callback** (JNI) and drop reliance on the one-shot
  `service.protect(wgGetSocketV4/V6(...))` (`GoBackend.java:349-350`) for WS tunnels — those now
  return `-1`. Keep them for the UDP path.
- **Register a `ConnectivityManager.registerNetworkCallback()`** and call the bump export on network
  change — the Android delivery of what the Apple app does with `NWPathMonitor` (WORK_PLAN D10/D19).
- **UI** — a way to enter the WS transport, server URL, mode, target, and bearer.

---

## 4. The protect-callback bridge (mechanism)

The only genuinely new plumbing is letting Go ask Java to `protect()` a freshly created socket fd.
Pattern:

1. **Register (once, at turn-on).** Java passes an object/callback down; the shim caches the
   `JavaVM*`, a global ref to the callback, and the `protect(int)` method ID.
2. **Per dial (Go side).** The WS bind's `net.Dialer.Control(network, address, c)` runs
   `c.Control(func(fd uintptr){ protectHook(int(fd)) })` **before** connect. `protectHook` calls a C
   function exported from `jni.c`.
3. **Upcall (C side).** That C function does `(*vm)->AttachCurrentThread(...)`, invokes the cached
   Java `protect(fd)` (which calls `VpnService.protect`), then detaches. Return value indicates success.

This mirrors, in reverse, the existing `wgGetSocketV4/V6` bridge — but push (Go→Java, per dial) instead
of pull (Java→Go, once).

---

## 5. Config on Android — summary

| WORK_PLAN placement (desktop) | On Android |
|---|---|
| `WG_TRANSPORT` (env/flag) | UAPI device key in the settings string, or a `wgTurnOn` param |
| TLS material (files/flags) | UAPI keys / `wgTurnOn` params; a mobile **client** usually needs only system roots + `servername` |
| `ws_ping_interval`, backoff (flags) | UAPI device keys (sane defaults if omitted) |
| `ws_listen`, `endpoint` URL, `ws_mode`, `ws_target`, `ws_bearer` (UAPI) | unchanged — already UAPI |

Everything funnels through `config.toWgUserspaceString()` → `wgTurnOn(settings)` → `IpcSet`.

---

## 6. Open items — resolved

- **JNI signature/lifecycle for the `VpnService.protect` upcall** — OUT OF THIS REPO'S SCOPE: it is
  Layer B/C plumbing (the user's wireguard-android fork). This repo's entire contract is the Layer A
  per-dial `func(fd int)` protect option; nothing in this repo depends on how the upcall is built.
- **Mobile client TLS** — RESOLVED: **system roots suffice** for the target deployment; no TLS config
  crosses the UAPI boundary (WORK_PLAN §4, TLS row, records the escalation paths if ever needed).
- Server role on Android is out of scope (the app is a client; `ws_listen` is unused there).
