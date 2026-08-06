<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 2 — WebSocket/wstunnel ⇄ UDP transport parity redesign

## Goal & scope

Make the WebSocket/wstunnel transport match the UDP transport in behaviour and feature set — per-peer model, fwmark cooperation, roaming, `get`/`set` round-trip — **differing only in the carrier**. Support **mixed peers** (UDP + WS/wstunnel on one device) and **simultaneous** WS client+server. Wire protocol (Noise, message types 1–4) is unchanged and stays interoperable with standard WireGuard.

Read `docs/PROJECT.md`, `docs/ARCHITECTURE.md`, and every `.claude/rules/*.md` before executing. This plan does NOT repeat information already in those documents.

### Decisions this plan implements (the design record)

- **Per-peer transport is explicit and mandatory.** New per-peer UAPI key `transport = udp | websocket | wstunnel`. A peer with no `transport` line is REJECTED (no default, no inference). `ws_mode` is REMOVED (its `websocket`/`wstunnel` distinction moves into `transport`). Device-wide `WG_TRANSPORT` env and `WS_ROLE` are REMOVED.
- **`endpoint = ip:port` for every transport** (resolved, routable — identical to UDP). The `wss://…` URL is no longer carried in `endpoint`.
- **`ws_url` (per-peer)** carries the full `ws(s)://host:port/path`, used ONLY for the TLS/HTTP layer: scheme ⇒ TLS on/off, host ⇒ SNI + `Host:` header + cert name, path ⇒ WS upgrade path. wireguard-go dials the exact `endpoint` ip:port (SNI/Host from `ws_url`) → no A-record race.
- **All client-connection settings are per-peer** UAPI keys, round-tripped via `get=1`: `ws_url`, `wstunnel_target`, `ws_bearer`, `ws_mask`, `ws_tls_ca`, `ws_tls_cert`, `ws_tls_key`, `ws_tls_insecure`, `ws_ping_interval`, `ws_backoff_min`, `ws_backoff_max`. TLS material is FILE PATHS.
- **Server/listener settings are device-level UAPI keys** (env retired): `ws_listen` (exists), `ws_server_tls_cert`, `ws_server_tls_key`, `ws_server_bearer`, `ws_trusted_proxies`. `WG_METRICS_LISTEN` stays env (operational, not tunnel config).
- **Simultaneous client+server** (drop `cfg.role`): a device is a WS server if `ws_listen` is set and a WS client toward any peer with `ws_url`; both at once. `ws_listen`↔`listen_port`, `ws_url`↔`endpoint`.
- **Mixed peers** via a multiplexing `conn.Bind` composing `StdNetBind` (UDP) + `WebSocketBind` (WS), dispatching per-peer by endpoint type. UDP data path unchanged (no regression); library consumers that pass their own bind are unaffected.
- **fwmark socket-side fix (the reported bug):** `WebSocketBind.SetMark` re-applies the mark to all live sockets (client + server) in place, plus marks at dial + accept, using the same per-OS ioctl UDP uses; no-op on darwin/windows.
- **darwin off-tun moves to `wg-quick` (host-route `endpoint=ip:port`).** The darwin `IP_BOUND_IF` pin is REMOVED (it is harmful under full-tunnel — `defaultEgressIfIndex()` can resolve to the `utun` and `IP_BOUND_IF` overrides the route). macOS end-to-end is Manual QA, coordinated with the wireguard-tools change.
- **UAPI is no longer required to be stock-`wg(8)`-compatible** (fork tooling drives it); wire-protocol interop stays sacred. `project.md` invariant updated accordingly.

### Cross-repo boundary (NOT in this plan — hand-off specs, not executed here)

`wireguard-tools`/`wireguard-android` (separate repos): author the per-peer `Transport` directive; resolve the URL host → emit `endpoint=ip:port` + `ws_url` + per-peer `ws_*` keys (or none for UDP peers); emit device-level `ws_server_*`/`ws_trusted_proxies`/`ws_listen`; drop `endpoint_url`/URL-in-endpoint. `darwin.bash`/`freebsd`/`openbsd` need NO change (they host-route `endpoint=ip:port` natively). These changes are the user's; this plan MUST NOT modify those repos.

### Testing strategy

- **Unit** (`conn/*_test.go`, `device/*_test.go`): OS-agnostic logic — per-peer dial-config building, transport-driven endpoint construction, multiplexing dispatch, simultaneous client+server, fwmark application via `fakeRawConn`, `get`/`set` round-trip. Standard library `testing` only; `-race`.
- **Linux netns e2e** (`tests/e2e/`, `//go:build linux && e2e`): mixed UDP+WS peers, WS full-tunnel with `fwmark` + `ip rule not fwmark` + default route (reproduces & validates the bug), wstunnel, simultaneous client+server.
- **Live docker integration (real server):** inside a docker container, connect to the user's **live** WireGuard server behind **wstunnel**, verified BOTH split-tunnel AND full-tunnel (`AllowedIPs=0.0.0.0/0`). Uses the user's real config/credentials (private key NEVER printed). This is part of "everything else tested and working" and runs during US9, before the post-implementation code review.
- **Manual QA (macOS) — the final gate, literally the last step before the PR.** Full-tunnel (`0.0.0.0/0`) over WS/wstunnel on a real Mac (the Linux netns harness cannot run macOS routing; gated on the wireguard-tools host-route change + darwin-pin removal). It runs **after** the post-implementation code review is clean AND after the live docker test passes — see "Release sequencing" below. It requires a real macOS network and the user's involvement (a network switch may be needed), so implementation MUST **STOP and notify the user** at that point and only open the PR after the user confirms the macOS test passes.

### Sequential execution order (no item depends on a later item)

US1 fwmark fix → US2 `WSEndpoint` per-peer dial config → US3 `WebSocketBind` per-peer dial + simultaneous client+server + device server settings → US4 multiplexing `conn.Bind` → US5 UAPI wiring (`transport`, `endpoint=ip:port`, per-peer + device keys, get/set round-trip) → US6 daemon wiring + env retirement → US7 remove darwin pin → US8 docs → US9 ground-up verification.

---

## User Story 1 — fwmark socket-side fix (the reported bug) `[ ]`

**Why:** `wg-quick` full-tunnel sets `fwmark` + `ip rule not fwmark table`; the WS TCP socket must carry the mark on every segment or it self-loops. `WebSocketBind.SetMark` currently only stores the mark for future dials and never re-marks live sockets, unlike UDP's `StdNetBind.SetMark` which re-marks its open sockets in place.

**Acceptance criteria:**
- `[ ]` `WebSocketBind.SetMark` re-applies the mark to every currently-open socket (client `conns` + server `sconns`), in place, matching UDP semantics.
- `[ ]` New dials (client) and accepted connections (server) carry the mark at creation.
- `[ ]` Per-OS socket option is the same `fwmarkIoctl` UDP uses: `SO_MARK` (linux/android), `SO_USER_COOKIE` (freebsd), `SO_RTABLE` (openbsd); no-op on darwin/windows.
- `[ ]` `*tls.Conn` is unwrapped to the underlying `*net.TCPConn` to reach the fd.
- `[ ]` Linux netns e2e proves WS + wstunnel full-tunnel (fwmark + `not fwmark` rule + default route) passes traffic.

### Task 1.1 — Per-OS socket-mark primitives `[ ]`

**Actions:**
- `[ ]` **create** `conn/ws_mark_unix.go` (`//go:build linux || freebsd || openbsd`): the mark primitives, reusing `fwmarkIoctl` from `mark_unix.go` (same build set).
  ```go
  package conn

  import (
      "fmt"
      "net"
      "syscall"

      "golang.org/x/sys/unix"
  )

  // markRawFd sets the per-OS fwmark socket option (fwmarkIoctl: SO_MARK/SO_USER_COOKIE/
  // SO_RTABLE) on fd. mark==0 clears it, matching StdNetBind.SetMark (mark_unix.go).
  func markRawFd(fd uintptr, mark uint32) error {
      if fwmarkIoctl == 0 {
          return nil
      }
      return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, int(mark))
  }

  // markConn applies the fwmark to c's underlying socket, unwrapping *tls.Conn to the
  // net.Conn that implements syscall.Conn.
  func markConn(c net.Conn, mark uint32) error {
      rc, err := rawConnOf(c)
      if err != nil {
          return err
      }
      var operr error
      if err := rc.Control(func(fd uintptr) { operr = markRawFd(fd, mark) }); err != nil {
          return err
      }
      return operr
  }

  // rawConnOf reaches the syscall.RawConn behind a net.Conn, unwrapping *tls.Conn
  // (which exposes NetConn()) down to the *net.TCPConn that implements syscall.Conn.
  // Co-located with its sole caller markConn (unused on darwin/windows otherwise).
  func rawConnOf(c net.Conn) (syscall.RawConn, error) {
      for {
          switch v := c.(type) {
          case syscall.Conn:
              return v.SyscallConn()
          case interface{ NetConn() net.Conn }:
              c = v.NetConn()
          default:
              return nil, fmt.Errorf("connection type %T exposes no raw fd", c)
          }
      }
  }
  ```
- `[ ]` **create** `conn/ws_mark_other.go` (`//go:build !linux && !freebsd && !openbsd`): no-op parity for darwin/windows (UDP no-ops mark there too). No `rawConnOf` here — `markConn` never unwraps.
  ```go
  package conn

  import "net"

  func markConn(_ net.Conn, _ uint32) error { return nil }
  ```

**Definition of Done:**
- `[ ]` Every supported `GOOS` (linux/darwin/windows/freebsd/openbsd) has a `markConn` implementation via the build-tag split (real on linux/freebsd/openbsd, no-op elsewhere); `rawConnOf` is defined once, on the mark OSes (linux/freebsd/openbsd) where its sole caller `markConn` uses it. Compilation is verified in US9.

### Task 1.2 — Live re-mark in SetMark + dial/accept marking `[ ]`

**Actions:**
- `[ ]` **modify** `conn/ws_bind.go` — `SetMark` stores and re-marks live sockets best-effort (store never fails; a live socket that can't be marked is logged and replaced on reconnect):
  ```go
  func (b *WebSocketBind) SetMark(mark uint32) error {
      b.mark.Store(mark)
      b.mu.Lock()
      conns := make([]net.Conn, 0, len(b.conns)+len(b.sconns))
      for _, c := range b.conns {
          conns = append(conns, c.wc.conn)
      }
      for _, sc := range b.sconns {
          conns = append(conns, sc.wc.conn)
      }
      b.mu.Unlock()
      for _, c := range conns {
          if err := markConn(c, mark); err != nil {
              b.cfg.logger.errorf("websocket: re-mark live socket: %v", err)
          }
      }
      return nil
  }
  ```
  (This adds a `net` import to `conn/ws_bind.go`, which currently imports only `context`/`fmt`/`net/http`/`net/url`/`sync`/`sync/atomic`/`time`.)
- `[ ]` **modify** `conn/ws_pinning_linux.go` → **rename to** `conn/ws_pinning_mark_unix.go` with `//go:build linux || freebsd || openbsd`, and route `dialControl` through `markRawFd` so freebsd/openbsd also mark on dial (linux behaviour unchanged; android note preserved):
  ```go
  //go:build linux || freebsd || openbsd
  package conn

  import (
      "syscall"
  )

  // dialControl marks each dialed socket with the per-OS fwmark (fwmarkIoctl) so policy
  // routing keeps the WebSocket transport off the tun, and invokes the optional protect
  // callback. On android (satisfies the linux tag) SO_MARK is unprivileged-safe and
  // protect delivers VpnService.protect. Recomputed on every dial.
  func (b *WebSocketBind) dialControl() func(network, address string, c syscall.RawConn) error {
      return func(network, address string, c syscall.RawConn) error {
          mark := b.mark.Load()
          var serr error
          cerr := c.Control(func(fd uintptr) {
              serr = markRawFd(fd, mark)
              if serr == nil && b.cfg.protect != nil {
                  b.cfg.protect(int(fd))
              }
          })
          if cerr != nil {
              return cerr
          }
          return serr
      }
  }
  ```
- `[ ]` **modify** `conn/ws_pinning_default.go`: narrow the build tag to `//go:build !darwin && !linux && !freebsd && !openbsd` (windows and other non-mark, non-darwin OSes keep the protect-only dialControl).
- `[ ]` **modify** `conn/ws_server.go` — in the upgrade handler, mark the accepted `netConn` before serving (server-side parity with client dial marking; no-op where `markConn` is a no-op):
  ```go
  // after a successful Upgrade, before serverReadLoop:
  if err := markConn(netConn, b.mark.Load()); err != nil {
      b.cfg.logger.errorf("websocket: mark accepted socket: %v", err)
  }
  ```

**Definition of Done:**
- `[ ]` `SetMark` re-marks all live client+server sockets and remains best-effort (never fails the UAPI op).
- `[ ]` Dial (all mark OSes) and accept apply the mark at creation.
- `[ ]` `conn/ws_pinning_darwin.go` (IP_BOUND_IF) is untouched here.

### Task 1.3 — Tests for the fwmark fix `[ ]`

| Test (file) | Verifies | Setup notes |
|---|---|---|
| `TestRawConnOf_UnwrapsTLSAndTCP` (`conn/ws_mark_internal_test.go`, `//go:build linux \|\| freebsd \|\| openbsd`) | `rawConnOf` returns a non-nil RawConn for a `*net.TCPConn` and for a `*tls.Conn` wrapping one | loopback `net.Pipe`/TCP pair + `tls.Client`; assert unwrap, not the setsockopt result (needs no privilege) |
| `TestWebSocketBind_SetMark_RemarksLiveConns` (`conn/ws_bind_test.go`) | `SetMark` iterates live `conns`+`sconns` and calls `markConn` on each without panicking; returns nil | inject fake `wsClientConn`/`wsServerConn` holding loopback `net.Conn`; assert no error + all visited |
| `TestWSDial_MarksSocket` (`conn/ws_pinning_*_test.go`) | `dialControl` invokes `markRawFd` with the stored mark and calls `protect` | move `fakeRawConn` out of the darwin-only `ws_pinning_darwin_test.go` (reworked in US7) into a file tagged `//go:build darwin \|\| linux \|\| freebsd \|\| openbsd` so BOTH this mark-OS test and US7's darwin protect test see it; set `b.mark`, assert Control path taken (privilege-free — assert the path, not the `setsockopt` result) |
| `TestWSServer_MarksAcceptedSocket` (`conn/ws_server_test.go`) | the accept-time `markConn(...)` code path runs on upgrade | assert the path is taken WITHOUT depending on a privileged `setsockopt` (use `mark=0` or a fake conn) — `SO_MARK` needs `CAP_NET_ADMIN` and `make test` is unprivileged |

The netns full-tunnel e2e cases (`TestE2E_WebSocket_FullTunnel`/`TestE2E_Wstunnel_FullTunnel`) that prove US1's acceptance are authored in US6 Task 6.2 (against the migrated harness + final UAPI model), to avoid a forward dependency.

**DoD:** `[ ]` US1 tests are written covering live re-mark, client-dial marking, server accept-time marking, and `*tls.Conn` unwrap (the netns full-tunnel cases land in US6; execution + `-race` deferred to US9).

---

## User Story 2 — `WSEndpoint` carries per-peer dial config `[ ]`

**Why:** Per-peer WS settings must travel on the endpoint so the dial path builds a per-peer TLS/dial config instead of one device-wide `cfg`.

**Acceptance criteria:**
- `[ ]` `WSEndpoint` carries `ws_url` + per-peer `wstunnel_target`, `bearer`, `mask`, `tlsCA`/`tlsCert`/`tlsKey` (paths), `tlsInsecure`, `pingInterval`, `backoffMin`, `backoffMax`, and the transport kind (`websocket`/`wstunnel`).
- `[ ]` A per-peer `*tls.Config` + dial parameters are built from the endpoint (lazily, cached) — never from the shared `cfg`.
- `[ ]` `endpoint` (ip:port) is the TCP target; `ws_url` supplies SNI/`Host`/path.

### Task 2.1 — Expand `WSEndpoint` and add the per-peer dial-config builder `[ ]`

**Actions:**
- `[ ]` **modify** `conn/ws_endpoint.go` — replace the client fields with the full per-peer set (keep server fields `dst`/`connID`):
  ```go
  type WSEndpoint struct {
      // client (outbound) fields — populated from per-peer UAPI keys:
      wsURL          string        // ws(s)://host:port/path — TLS scheme + SNI/Host + path
      dialTarget     netip.AddrPort // resolved endpoint= ip:port actually dialed
      dialect        wsDialect     // wsDialectStandard | wsDialectWstunnel (from transport)
      wstunnelTarget string        // wstunnel mode: inner WG host:port (JWT r/rp)
      bearer         string        // echoed by IpcGet, never logged
      mask           bool
      tlsCAPath      string
      tlsCertPath    string        // mTLS client cert (optional)
      tlsKeyPath     string        // mTLS client key (optional)
      tlsInsecure    bool
      pingInterval   time.Duration
      backoffMin     time.Duration
      backoffMax     time.Duration

      // server (inbound) fields:
      dst    netip.AddrPort // client remote (or XFF) addr
      connID uint64         // identifies the live accepted connection for Send dispatch
  }
  ```
- `[ ]` **modify** `conn/ws_endpoint.go` — `DstToString` returns the resolved `dialTarget` ip:port for client endpoints (routable, matches UDP), the `dst` for server endpoints; `DstToBytes`/`DstIP` use `dialTarget` for clients (stable MAC2 cookie key), `dst` for servers. `WSConfig` is REPLACED by per-peer getters used by `get=1` (Task 5.x).
- `[ ]` **modify** `conn/ws_endpoint.go` — add unexported cache fields to `WSEndpoint`: `dcOnce sync.Once`, `dc *dialConfig`, `dcErr error` (endpoints are immutable after set, so the built config is cached once).
- `[ ]` **create** `conn/ws_dialcfg.go`: builds the per-endpoint dial config (host/SNI/path from `wsURL`, `*tls.Config` from the paths + `tlsInsecure`, mTLS from cert/key paths), while the actual TCP connect goes to `dialTarget` (the dialer's `NetDial` override, Task 3.1). The dialect-specific dial URL / subprotocols / JWT are what `wsUpgradeRequest` builds today.
  ```go
  type dialConfig struct {
      dialURL   string      // wsURL with the wstunnel /<prefix>/events path applied when needed
      host      string      // wsURL host — TLS SNI + HTTP Host header
      tls       *tls.Config // built from tlsCAPath/tlsCertPath/tlsKeyPath/tlsInsecure; nil for ws://
      subprotos []string
      header    http.Header
  }

  func (e *WSEndpoint) dialConfig() (*dialConfig, error) {
      e.dcOnce.Do(func() { e.dc, e.dcErr = buildDialConfig(e) })
      return e.dc, e.dcErr
  }

  func buildDialConfig(e *WSEndpoint) (*dialConfig, error) {
      u, err := url.Parse(e.wsURL)
      if err != nil {
          return nil, fmt.Errorf("ws_url %q: %w", e.wsURL, err)
      }
      dc := &dialConfig{host: u.Host}
      if u.Scheme == "wss" {
          t := &tls.Config{ServerName: hostnameOnly(u.Host), InsecureSkipVerify: e.tlsInsecure}
          if e.tlsCAPath != "" { /* os.ReadFile → x509 pool → t.RootCAs */ }
          if e.tlsCertPath != "" || e.tlsKeyPath != "" { /* tls.LoadX509KeyPair → t.Certificates (mTLS) */ }
          dc.tls = t
      }
      // dc.dialURL / dc.subprotos / dc.header per dialect (standard: verbatim URL + optional Bearer;
      // wstunnel: /<prefix>/events + Sec-WebSocket-Protocol v1,authorization.bearer.<JWT>), reusing the
      // existing wsUpgradeRequest logic but reading fields from e.
      return dc, nil
  }

  // hostnameOnly returns host without the port, for TLS SNI. Defined here (first use).
  func hostnameOnly(hostport string) string {
      if h, _, err := net.SplitHostPort(hostport); err == nil {
          return h
      }
      return hostport
  }
  ```

### Task 2.2 — `WSEndpoint` white-box tests `[ ]`

| Test (file) | Verifies | Setup notes |
|---|---|---|
| `TestWSEndpoint_DstToString_ClientResolved` (`conn/ws_endpoint_internal_test.go`) | client endpoint reports the resolved `dialTarget` ip:port (not the URL); server endpoint reports `dst` | table: client vs server endpoints |
| `TestWSDialCfg_BuildsFromURL` (`conn/ws_dialcfg_test.go`) | host/port/path/SNI parsed from `wsURL`; TLS on for `wss`, off for `ws`; `tlsInsecure` sets `InsecureSkipVerify`; connect address = `dialTarget` | temp CA/cert/key files via `os.MkdirTemp`; standard + wstunnel dialects |
| `TestWSDialCfg_MTLS` (`conn/ws_dialcfg_test.go`) | client cert/key paths load into `tls.Config.Certificates`; missing/invalid paths error clearly | generate a throwaway cert/key pair in a temp dir |

**DoD:** `[ ]` per-peer dial config is derived solely from the endpoint (tests written; execution deferred to US9).

---

## User Story 3 — `WebSocketBind`: per-peer dial + simultaneous client+server + device server settings `[ ]`

**Why:** The bind must dial using the endpoint's per-peer config, run the listener and per-peer dialers simultaneously (drop `cfg.role`), and take server/listener settings as device-level configuration.

**Acceptance criteria:**
- `[ ]` `cfg.role` is REMOVED. A listener runs whenever `ws_listen` is set; dialing happens for any peer with a `ws_url` endpoint; both coexist.
- `[ ]` `Send` dispatches by `WSEndpoint` kind: `wsURL != ""` ⇒ outbound dialed conn (keyed by URL); else `connID != 0` ⇒ accepted conn.
- `[ ]` The client dial uses the endpoint's per-peer dial config (Task 2), connecting to `dialTarget` with SNI/Host/path from `wsURL`.
- `[ ]` Server settings (`ws_server_tls_cert/key`, `ws_server_bearer`, `ws_trusted_proxies`) are set via device-level setters on the bind, not env.

### Task 3.1 — Remove the role gate; run listener + dialers together `[ ]`

**Actions:**
- `[ ]` **modify** `conn/ws_config.go` — remove `role` and the client-scalar defaults now living per-peer (`tlsClient`, `maskFrames`, `pingInterval`, `backoffMin`, `backoffMax`); keep device/listener fields (`listenURL`, `serverBearer`, `trustedProxies`, `protect`, `logger`). Remove `WithWSRole`, the retired client options, AND the now-orphaned exported `WSRole` type + `WSRoleClient`/`WSRoleServer` constants (zero references after `buildWSOptionsFromEnv` is gone — dead exported API). Replace the `wsConfig.tlsServer *tls.Config` field with `serverCertPath`/`serverKeyPath` strings (and DROP the `WithWSServerTLS` option — library users now configure paths). Add device-level setters used by the UAPI: `SetServerCertPath(string)`, `SetServerKeyPath(string)`, `SetServerBearer(string)`, `SetTrustedProxies([]netip.Prefix)` — each writes its `b.cfg` field under `b.mu` (mirroring `SetWSListen`, `conn/ws_bind.go:132-142`). Storing the cert/key as PATHS means `ws_server_tls_cert` and `ws_server_tls_key` need NO cross-line buffering; `openServer` loads the keypair from the stored paths at Open (which also removes the `tlsServer` race, since the serve goroutine reads a local built config). Get reporters: `WSServerTLSPaths() (cert, key string)`, `WSServerBearer() string`, `WSTrustedProxies() []netip.Prefix` (each under `b.mu`).
  ```go
  func (b *WebSocketBind) SetServerCertPath(p string)         { b.mu.Lock(); b.cfg.serverCertPath = p; b.mu.Unlock() }
  func (b *WebSocketBind) SetServerKeyPath(p string)          { b.mu.Lock(); b.cfg.serverKeyPath = p; b.mu.Unlock() }
  func (b *WebSocketBind) SetServerBearer(tok string)         { b.mu.Lock(); b.cfg.serverBearer = tok; b.mu.Unlock() }
  func (b *WebSocketBind) SetTrustedProxies(p []netip.Prefix) { b.mu.Lock(); b.cfg.trustedProxies = p; b.mu.Unlock() }
  func (b *WebSocketBind) WSServerBearer() string             { b.mu.Lock(); defer b.mu.Unlock(); return b.cfg.serverBearer }
  func (b *WebSocketBind) WSTrustedProxies() []netip.Prefix   { b.mu.Lock(); defer b.mu.Unlock(); return b.cfg.trustedProxies }
  func (b *WebSocketBind) WSServerTLSPaths() (string, string) { b.mu.Lock(); defer b.mu.Unlock(); return b.cfg.serverCertPath, b.cfg.serverKeyPath }
  ```
- `[ ]` **modify** `conn/ws_server.go` — `openServer` MUST, under `b.mu`, capture `serverCertPath`, `serverKeyPath`, `serverBearer`, `trustedProxies` into per-server LOCALS (as it already does for `listenURL`); when both cert+key paths are set, `tls.LoadX509KeyPair(certPath, keyPath)` → build a local `*tls.Config` → set `srv.TLSConfig` and serve via `ServeTLS`, else plain `Serve`. Every closure MUST close over those locals — because these `b.cfg` fields are read OUTSIDE `b.mu` today: `checkBearer` (`ws_server.go:98`, `serverBearer`) and `resolveClientAddr` (`ws_server.go:47`, `trustedProxies`) run in the per-request handler goroutine, and the serve goroutine chooses TLS-vs-plain (`ws_server.go:85`) — all data races against the UAPI setters once those fields are mutable. The serve goroutine tests the LOCAL `srv.TLSConfig`, never `b.cfg`. A UAPI change takes effect on the next `BindUpdate` re-open (Task 5.2 calls `BindUpdate`), matching how `ws_listen` applies. Loading from paths at Open also means `SetServerCertPath`/`SetServerKeyPath` never touch a live config.
- `[ ]` **modify** `conn/ws_bind.go` `NewWebSocketBind`: drop the initialisers for the removed `wsConfig` fields (`cfg := wsConfig{pingInterval: …, backoffMin: …, backoffMax: …}` at `conn/ws_bind.go:87-92`) — those defaults now live per-endpoint (Task 4.1 `orDefault`), so `NewWebSocketBind` just applies the options.
- `[ ]` **modify** `conn/ws_client.go` `Open`: always initialise the client maps (`conns`, `dialBackoff`) AND, when `cfg.listenURL != ""`, start the server listener (call `openServer` for its listener/receiver) — both return receive funcs that feed the shared `inbound`. Remove the `role` branch.
- `[ ]` **modify** `conn/ws_client.go` `Send`: dispatch by endpoint kind (URL ⇒ `clientConn`+dial; `connID` ⇒ `serverSend`) instead of by `cfg.role`.
- `[ ]` **modify** `conn/ws_dial.go` `dial`: build `dialURL`, TLS config, subprotocols, and the connect address from the endpoint's per-peer dial config (Task 2), not from `cfg`. `NetDial` connects to `we.dialTarget` regardless of the URL host (SNI/Host still from `wsURL`). Set the created `wsConn.mask` from `we.mask` (per-peer masking; `cfg.maskFrames` is removed).
- `[ ]` **modify** `conn/ws_dialect.go` / `conn/ws_jwt.go`: `wstunnelJWT` and the upgrade request read `wsURL`/`wstunnelTarget`/`bearer` from the endpoint.
- `[ ]` **modify** `conn/ws_ping.go` — `pingLoop` reads the per-peer interval `c.ep.pingInterval` (not `b.cfg.pingInterval`); a zero/absent interval falls back to the package default.
- `[ ]` **modify** `conn/ws_dial.go` `clientConn` — the reconnect backoff reads the per-peer `we.backoffMin`/`we.backoffMax` (not `b.cfg.backoffMin`/`b.cfg.backoffMax`).
- `[ ]` **Per-peer timing defaults:** `ParseWSPeerEndpoint` normalises the endpoint so that absent `ws_ping_interval`/`ws_backoff_min`/`ws_backoff_max` are filled with the existing package constants (`wsDefaultPingInterval`/`wsDefaultBackoffMin`/`wsDefaultBackoffMax`) — the retired `cfg` defaults move onto the endpoint. Keep the constants in `conn/ws_config.go`.
- `[ ]` **modify** `conn/ws_dial.go` + `conn/ws_client.go` — key `b.conns`/`b.dialBackoff` by the per-peer **dial identity**, not `ws_url` alone: a stable key derived from `dialTarget` + `wsURL` (+ `wstunnelTarget`), so two peers sharing a `ws_url` but with different `dialTarget`/`wstunnelTarget` never collide on one connection. Add a `key()` method on `*WSEndpoint`; update the map reads/writes and the `readLoop` deregistration (currently `b.conns[c.ep.url]`) to use it.

### Task 3.2 — Tests `[ ]`

| Test (file) | Verifies | Setup notes |
|---|---|---|
| `TestWSBind_Simultaneous_ClientAndServer` (`conn/ws_server_test.go`) | one bind with `ws_listen` set accepts an inbound peer AND dials an outbound `ws_url` peer; both deliver to `inbound` | in-process `httptest`/loopback server for the outbound side; a fake client dialing the listener for the inbound side |
| `TestWSBind_Send_DispatchByEndpointKind` (`conn/ws_bind_test.go`) | `Send` to a URL endpoint dials; `Send` to a `connID` endpoint uses the accepted conn; wrong/zero endpoint errors | table of endpoint kinds |
| `TestWSDial_UsesPerPeerTLSAndTarget` (`conn/ws_internal_test.go`) | dial connects to `dialTarget`, sets SNI/`Host` from `wsURL`, applies per-peer TLS/insecure | `httptest.NewTLSServer`; assert SNI via server `GetConfigForClient` |
| update the existing listener-persistence test in `conn/ws_server_test.go` | listener persists when a full-replace setconf omits `ws_listen`, under the simultaneous-role bind | migrate the existing coverage to the roleless bind + new UAPI model |
| `TestWSEndpoint_KeyDistinguishesPeers` (`conn/ws_endpoint_internal_test.go`) | two endpoints sharing `wsURL` but with different `dialTarget`/`wstunnelTarget` produce different `key()`s (no connection-map collision) | table |
| `TestWSDial_PerPeerTimingDefaults` (`conn/ws_dialcfg_test.go` or `ws_internal_test.go`) | absent `ws_ping_interval`/`ws_backoff_*` normalise to the package defaults on the built endpoint | assert normalised values |

**DoD:** `[ ]` no `cfg.role` remains; client+server run together; `Send` dispatch is endpoint-driven; per-peer timings and connection keying are honoured (tests written; execution deferred to US9).

---

## User Story 4 — Multiplexing `conn.Bind` (mixed UDP + WS peers) `[ ]`

**Why:** A device must carry UDP and WS/wstunnel peers at once, dispatching each peer to the right transport by endpoint type, with the UDP data path unchanged.

**Acceptance criteria:**
- `[ ]` A `multiplexBind` composes a `StdNetBind` and a `WebSocketBind` and implements `conn.Bind`.
- `[ ]` `Send` dispatches by endpoint type (`*StdNetEndpoint` ⇒ UDP; `*WSEndpoint` ⇒ WS). `Open` returns the union of both sub-binds' receive funcs. `SetMark`/`Close`/`SetMark`/port fan out correctly. `BatchSize` reports the UDP sub-bind's size.
- `[ ]` `PeekLookAtSocketFd` / windows `BindSocketToInterface` forward to the UDP sub-bind.
- `[ ]` A transport-aware endpoint builder lets the UAPI construct the right endpoint type from `(transport, endpoint, wsPeerConfig)`.
- `[ ]` Pure-UDP behaviour is unchanged. The WS sub-bind is ALWAYS opened by `multiplexBind.Open` (cheap: inbound channel + maps, no sockets) so a WS peer added by `wg set` after the interface is up is immediately dialable; only the HTTP **listener** is conditional (on `ws_listen`, already handled inside `openServer`). No `device`-peer visibility is required.

### Task 4.1 — `multiplexBind` `[ ]`

**Actions:**
- `[ ]` **create** `conn/ws_multiplex.go`:
  ```go
  type multiplexBind struct {
      udp Bind           // NewDefaultBind() — WinRingBind on windows, StdNetBind elsewhere (UDP path UNCHANGED)
      ws  *WebSocketBind
  }

  func NewMultiplexBind(wsOpts ...WSOption) (*multiplexBind, error) { /* udp: NewDefaultBind(); ws: NewWebSocketBind(wsOpts...) */ }

  // Send dispatches by endpoint concrete type.
  func (m *multiplexBind) Send(bufs [][]byte, ep Endpoint) error {
      switch ep.(type) {
      case *WSEndpoint:
          return m.ws.Send(bufs, ep)
      default:
          return m.udp.Send(bufs, ep) // any non-WS endpoint → the platform UDP bind
      }
  }
  ```
  - The UDP sub-bind is held as `conn.Bind` from `NewDefaultBind()` so the **platform** UDP bind is preserved (Windows keeps `WinRingBind`; UDP data path unchanged). Optional-interface forwarders (below) type-assert on `m.udp`.
  - `Open(port)`: open the UDP sub-bind (returns its receive funcs + port); ALWAYS open the WS sub-bind and append its receive funcs (its `Open` allocates the inbound channel/maps and starts the HTTP listener only if `ws_listen` is set — a WS peer added later is dialable without a re-Open). Return the union + the UDP port.
  - `Close`/`SetMark`: fan out to both (aggregate errors). `BatchSize`: UDP's. `ParseEndpoint`: UDP (plain `ip:port`) by default; the transport-aware builder (below) handles WS.
- `[ ]` **modify** `conn/ws_multiplex.go` — add `WSInUse() bool` on `multiplexBind`, forwarding to the WS sub-bind: true iff `ws_listen` is configured OR any WS client/server connection is open (read the `WebSocketBind` state under `b.mu`). The daemon's path monitor uses it to avoid reopening a pure-UDP bind on network changes (preserves the UDP-unchanged invariant).
- `[ ]` **create** build-tagged forwarder files so the multiplex bind exposes the SAME optional interfaces the platform UDP bind does — declared ONLY where the UDP bind has them (else a cross-GOOS build break): `PeekLookAtSocketFd4/6` forwarders in a `//go:build android` file (mirrors `StdNetBind` in `conn/boundif_android.go`); `BindSocketToInterface4/6` forwarders in a `//go:build windows` file (mirrors `WinRingBind` in `conn/bind_windows.go`). Each asserts the interface on `m.udp` and forwards.
- `[ ]` **modify** `conn/ws_multiplex.go` — `multiplexBind` MUST also implement and forward to `m.ws` every interface the device UAPI type-asserts on `device.net.bind`: `WebSocketBinder` (`SetWSListen`, `ParseWSPeerEndpoint`, and the new `SetServerCertPath`/`SetServerKeyPath`/`SetServerBearer`/`SetTrustedProxies` — defined on `WebSocketBind` in US3 Task 3.1, added to the `WebSocketBinder` interface in US5 Task 5.2), the `wsListenReporter` get interface, and the device-level WS get reporters (`WSServerTLSPaths`/`WSServerBearer`/`WSTrustedProxies`) — otherwise the `ws_*` UAPI assertions fail against the multiplex bind. Also implement `WebSocketMetricsProvider` (forward `WSMetricsSnapshot` to `m.ws`) so `startMetrics` keeps working.
- `[ ]` **modify** `conn/ws_bind.go` — add the `WebSocketBinder` method the UAPI uses to build a WS endpoint from per-peer config, replacing the old positional `ParseWSPeerEndpoint(rawURL, mode, wstunnelTarget, bearer)`. `WSPeerConfig` is an EXPORTED struct with only exported/`string` fields so the `device` package can construct it (the internal `wsDialect` is derived inside `ParseWSPeerEndpoint` from the `Transport` string — the `device` package cannot set an unexported `wsDialect`):
  ```go
  // WSPeerConfig carries a peer's per-connection WebSocket settings from the UAPI.
  type WSPeerConfig struct {
      Endpoint       netip.AddrPort // resolved ip:port to dial (from endpoint=)
      Transport      string         // "websocket" | "wstunnel" — mapped to the internal dialect
      URL            string         // ws_url
      WstunnelTarget string         // wstunnel only
      Bearer         string
      Mask           bool
      TLSCAPath      string
      TLSCertPath    string
      TLSKeyPath     string
      TLSInsecure    bool
      PingInterval   time.Duration
      BackoffMin     time.Duration
      BackoffMax     time.Duration
  }

  func (b *WebSocketBind) ParseWSPeerEndpoint(cfg WSPeerConfig) (Endpoint, error) {
      e := &WSEndpoint{
          wsURL: cfg.URL, dialTarget: cfg.Endpoint, wstunnelTarget: cfg.WstunnelTarget,
          bearer: cfg.Bearer, mask: cfg.Mask, tlsCAPath: cfg.TLSCAPath,
          tlsCertPath: cfg.TLSCertPath, tlsKeyPath: cfg.TLSKeyPath, tlsInsecure: cfg.TLSInsecure,
      }
      switch cfg.Transport {
      case "websocket":
          e.dialect = wsDialectStandard
          if cfg.WstunnelTarget != "" {
              return nil, fmt.Errorf("wstunnel_target requires transport=wstunnel")
          }
      case "wstunnel":
          e.dialect = wsDialectWstunnel
          if cfg.WstunnelTarget == "" {
              return nil, fmt.Errorf("transport=wstunnel requires wstunnel_target")
          }
      default:
          return nil, fmt.Errorf("invalid websocket transport %q", cfg.Transport)
      }
      // orDefault(d, def) returns def when d==0; defined in this file (Task 4.1).
      e.pingInterval = orDefault(cfg.PingInterval, wsDefaultPingInterval)
      e.backoffMin = orDefault(cfg.BackoffMin, wsDefaultBackoffMin)
      e.backoffMax = orDefault(cfg.BackoffMax, wsDefaultBackoffMax)
      return e, nil
  }

  // orDefault returns def when d is zero. Defined here (first use).
  func orDefault(d, def time.Duration) time.Duration {
      if d == 0 {
          return def
      }
      return d
  }
  ```
- `[ ]` **modify** `conn/ws_bind.go` — update `WebSocketBind.ParseEndpoint` (the mandatory `conn.Bind` method, today calling the old positional form): under the new model it parses a plain `ip:port` into `&WSEndpoint{dialTarget: ap}` with normalised default timings and no `wsURL` (the primary WS path is `ParseWSPeerEndpoint`; in the daemon, plain endpoints route to UDP via the multiplex bind, so this only serves standalone/library `WebSocketBind` use).
- `[ ]` **remove** `conn/default_ws.go` — its sole function `NewBindForTransport(transport, opts…)` existed only to pick udp-vs-ws from the now-retired `WG_TRANSPORT`; it has no place in the per-peer model (verify no other caller via `git grep NewBindForTransport`). The daemon constructs the bind via `conn.NewMultiplexBind(...)` (Task 6.1). Library consumers construct `NewStdNetBind()`/`NewWebSocketBind()`/`NewMultiplexBind()` directly and are unaffected. Removal authorised by this plan's approval.

### Task 4.2 — Tests `[ ]`

| Test (file) | Verifies | Setup notes |
|---|---|---|
| `TestMultiplexBind_Send_DispatchByType` (`conn/ws_multiplex_test.go`) | `*StdNetEndpoint`→UDP sub-bind, `*WSEndpoint`→WS sub-bind | fake sub-binds recording calls |
| `TestMultiplexBind_Open_UnionReceiveFuncs` (`conn/ws_multiplex_test.go`) | `Open` ALWAYS returns both sub-binds' receive funcs (WS sub-bind always opened); only the HTTP listener is conditional on `ws_listen` | assert the union always includes the WS receive func; assert the listener starts only with `ws_listen` set |
| `TestMultiplexBind_SetMarkCloseFanout` (`conn/ws_multiplex_test.go`) | `SetMark`/`Close` reach both sub-binds; `BatchSize`==UDP's | fakes |
| `TestMultiplexBind_ForwardsPeek` (`conn/ws_multiplex_test.go`, `//go:build android`) | `PeekLookAtSocketFd` forwards to the UDP sub-bind | interface assertion |
| `TestMultiplexBind_ForwardsBindSocketToInterface` (`conn/ws_multiplex_test.go`, `//go:build windows`) | `multiplexBind` implements `conn.BindSocketToInterface` and forwards `BindSocketToInterface4/6` to the UDP sub-bind | interface assertion on the windows forwarder |

**DoD:** `[ ]` UDP-only path bit-for-bit unchanged (dispatch default = UDP); `multiplexBind` forwards all `WebSocketBinder`/reporter/metrics interfaces to `m.ws` (tests written; execution deferred to US9).

---

## User Story 5 — UAPI wiring: `transport`, `endpoint=ip:port`, per-peer + device keys, round-trip `[ ]`

**Why:** The device core must parse the explicit per-peer `transport`, build the right endpoint type via the multiplexing bind, accept the per-peer/device WS keys, and round-trip them via `get=1`.

**Acceptance criteria:**
- `[ ]` `set=1`: `transport` (per-peer, values `udp|websocket|wstunnel`) is MANDATORY at peer **creation** — creating a peer with no `transport` line is rejected with a clear error; an incremental update of an existing peer may omit it and keeps the peer's persisted transport (matches UDP incremental updates). `transport` is persisted on `Peer`. `ws_mode` is REMOVED.
- `[ ]` `endpoint=ip:port` is parsed as a plain address for all transports; the endpoint TYPE is chosen by `transport`. `endpoint`/`ws_url` are OPTIONAL (an inbound peer has neither — its endpoint is learned on accept, like a UDP peer with no `endpoint`); a dialing WS peer requires both `ws_url` and `endpoint`.
- `[ ]` Per-peer keys `ws_url`, `wstunnel_target`, `ws_bearer`, `ws_mask`, `ws_tls_ca`, `ws_tls_cert`, `ws_tls_key`, `ws_tls_insecure`, `ws_ping_interval`, `ws_backoff_min`, `ws_backoff_max` are collected and consumed in `handlePostConfig`.
- `[ ]` Device keys `ws_server_tls_cert`, `ws_server_tls_key`, `ws_server_bearer`, `ws_trusted_proxies` are handled at device level (alongside `ws_listen`).
- `[ ]` `get=1` emits `transport=` for every peer and round-trips all per-peer + device keys (secrets: `ws_bearer` echoed, never logged; key material never logged).

### Task 5.1 — `set=1` per-peer transport + keys `[ ]`

**Actions:**
- `[ ]` **modify** `device/peer.go` — add a persisted per-peer transport field `transport peerTransport` on `Peer`, where `peerTransport` is a **string-backed** type so `sendf("transport=%s", …)` renders directly and it is the exact inverse of `parsePeerTransport` (a config attribute, NOT OS logic):
  ```go
  type peerTransport string
  const (
      peerTransportUDP       peerTransport = "udp"
      peerTransportWebSocket peerTransport = "websocket"
      peerTransportWstunnel  peerTransport = "wstunnel"
  )
  ```
  Set at creation/update from the UAPI (via `parsePeerTransport`); read by `get`.
- `[ ]` **modify** `device/uapi.go` `ipcSetPeer`: replace `wsEndpointURL`/`wsMode` collection with `transport string` + `transportSeen bool`, `endpointStr string` + `endpointSeen bool` (NOT `endpoint` — `ipcSetPeer` embeds `*Peer`, whose promoted `endpoint struct{…}` field would be shadowed; keep `peer.Peer.endpoint.*` for the real endpoint), and the full per-peer WS key set (`wsURL`, `wstunnelTarget`, `wsBearer`, `wsMask`, `wsTLSCA`, `wsTLSCert`, `wsTLSKey`, `wsTLSInsecure`, `wsPingInterval`, `wsBackoffMin`, `wsBackoffMax`) PLUS presence tracking for EVERY `ws_*` key (a `wsSeen map[string]bool` populated as each key is parsed) — bool/duration keys have ambiguous zero values, so presence cannot be inferred from the value; this is what lets `handlePostConfig` reject any `ws_*` key under `transport=udp`. Reset all (including `wsSeen`) in `handlePublicKeyLine`.
- `[ ]` **modify** `device/uapi.go` `handlePeerLine`: add `case "transport"` (validate `udp|websocket|wstunnel`, store + set `transportSeen`); `case "endpoint"` stores the raw value + sets `endpointSeen` (parse deferred to `handlePostConfig` so key order is irrelevant); add the per-peer `ws_*` cases; REMOVE `case "ws_mode"`.
- `[ ]` **modify** `device/uapi.go` `handlePostConfig` — resolve the effective transport and build the endpoint:
  - **Mandatory only at creation** (matches UDP incremental updates): if `peer.created && !transportSeen` ⇒ `ipcErrorf(ipc.IpcErrorInvalid, "peer missing mandatory transport")`. If `transportSeen`, validate + persist onto `peer.transport`; else (existing-peer update) use the peer's persisted `peer.transport`.
  - `transport==udp`: reject any `ws_*` key; if `endpointSeen` ⇒ `device.net.bind.ParseEndpoint(endpoint)` and set `peer.endpoint.val`; if absent, leave the endpoint unset (inbound/roaming, exactly like UDP).
  - `transport==websocket|wstunnel`: **`ws_url` is OPTIONAL** — its presence follows the `ws_url`↔`endpoint` analogy (present ⇒ we dial; absent ⇒ inbound peer whose endpoint is learned on accept, like a UDP peer with no `endpoint`). If `ws_url` present: require `endpointSeen` (the resolved ip:port to dial), assert `conn.WebSocketBinder`, and `binder.ParseWSPeerEndpoint(WSPeerConfig{...})` (dialect from `transport`; for `wstunnel` require `wstunnel_target`); set `peer.endpoint.val`. If `ws_url` absent: build no dial endpoint (record the transport only). `wstunnel_target` is rejected unless `transport==wstunnel` with `ws_url` present.
  ```go
  func (peer *ipcSetPeer) handlePostConfig() error {
      if peer.Peer == nil || peer.dummy {
          return nil
      }
      if peer.transportSeen {
          t, err := parsePeerTransport(peer.transport) // "udp"|"websocket"|"wstunnel" → peerTransport*
          if err != nil {
              return ipcErrorf(ipc.IpcErrorInvalid, "invalid transport: %w", err)
          }
          peer.Peer.transport = t
      } else if peer.created {
          return ipcErrorf(ipc.IpcErrorInvalid, "peer missing mandatory transport")
      }
      switch peer.Peer.transport {
      case peerTransportUDP:
          if peer.anyWSKeySeen() { // any ws_* in wsSeen
              return ipcErrorf(ipc.IpcErrorInvalid, "ws_* keys not allowed for transport=udp")
          }
          if peer.endpointSeen {
              ep, err := peer.device.net.bind.ParseEndpoint(peer.endpointStr)
              if err != nil {
                  return ipcErrorf(ipc.IpcErrorInvalid, "failed to set endpoint %v: %w", peer.endpointStr, err)
              }
              peer.setEndpoint(ep)
          }
      case peerTransportWebSocket, peerTransportWstunnel:
          if peer.wsSeen["ws_url"] { // dialing peer
              if !peer.endpointSeen {
                  return ipcErrorf(ipc.IpcErrorInvalid, "dialing websocket peer requires endpoint")
              }
              ap, err := netip.ParseAddrPort(peer.endpointStr)
              if err != nil {
                  return ipcErrorf(ipc.IpcErrorInvalid, "invalid endpoint %q: %w", peer.endpointStr, err)
              }
              binder, ok := peer.device.net.bind.(conn.WebSocketBinder)
              if !ok {
                  return ipcErrorf(ipc.IpcErrorInvalid, "websocket transport not available")
              }
              ep, err := binder.ParseWSPeerEndpoint(conn.WSPeerConfig{
                  // Transport from the EFFECTIVE persisted enum (string-backed), NOT the raw
                  // ipcSetPeer.transport, so an incremental update that omits transport= but
                  // re-sends ws_url still builds correctly (decision 1).
                  Endpoint: ap, Transport: string(peer.Peer.transport), URL: peer.wsURL,
                  WstunnelTarget: peer.wstunnelTarget, Bearer: peer.wsBearer, Mask: peer.wsMask,
                  TLSCAPath: peer.wsTLSCA, TLSCertPath: peer.wsTLSCert, TLSKeyPath: peer.wsTLSKey,
                  TLSInsecure: peer.wsTLSInsecure, PingInterval: peer.wsPingInterval,
                  BackoffMin: peer.wsBackoffMin, BackoffMax: peer.wsBackoffMax,
              })
              if err != nil {
                  return ipcErrorf(ipc.IpcErrorInvalid, "failed to build websocket endpoint: %w", err)
              }
              peer.setEndpoint(ep)
          } else if peer.wsSeen["wstunnel_target"] { // inbound peer must not carry a dial target
              return ipcErrorf(ipc.IpcErrorInvalid, "wstunnel_target requires ws_url")
          }
      }
      // ...existing created/roaming + isUp Start/keepalive/SendStagedPackets tail unchanged
      //    (uses peer.Peer.endpoint.*, NOT the shadow endpointStr) ...
      return nil
  }
  ```
- `[ ]` **add** the small helpers referenced above (all in `device/uapi.go` unless noted): `parsePeerTransport(string) (peerTransport, error)` (maps `udp`/`websocket`/`wstunnel`, errors otherwise); `(*ipcSetPeer) anyWSKeySeen() bool` (any key in `wsSeen`); `(*ipcSetPeer) setEndpoint(conn.Endpoint)` (locks `peer.Peer.endpoint`, sets `.val`); `(*Device) wsBinder() (conn.WebSocketBinder, error)` (type-asserts `device.net.bind`, else `ipcErrorf(ipc.IpcErrorInvalid, "requires the websocket transport")`); `parseCIDRList(string) ([]netip.Prefix, error)`. (The `conn` helpers `orDefault` and `hostnameOnly` are defined in their first-use tasks — Task 4.1 and Task 2.1 respectively — to avoid a forward dependency.)

### Task 5.2 — device-level server keys `[ ]`

**Actions:**
- `[ ]` **modify** `device/uapi.go` device switch (near `ws_listen`): add INDEPENDENT `case "ws_server_tls_cert"` (→ `b.SetServerCertPath(value)`) and `case "ws_server_tls_key"` (→ `b.SetServerKeyPath(value)`) — no cross-line buffering (paths stored on the bind, loaded together at Open); `case "ws_server_bearer"` (→ `b.SetServerBearer(value)`; verbose log the KEY NAME ONLY, never the value — secret, per "NO SECRETS IN LOGS"); `case "ws_trusted_proxies"` (→ `parseCIDRList` → `b.SetTrustedProxies`). Each calls `device.BindUpdate()` after (as `ws_listen` does) so the listener reopens with the new server config. Extend `conn.WebSocketBinder` with `SetServerCertPath`/`SetServerKeyPath`/`SetServerBearer`/`SetTrustedProxies` (+ the get reporters).
  ```go
  // in the device-level key switch; `wsBinder()` asserts conn.WebSocketBinder or returns an ipc error.
  case "ws_server_tls_cert":
      b, err := device.wsBinder(); if err != nil { return err }
      b.SetServerCertPath(value)
      if err := device.BindUpdate(); err != nil { return ipcErrorf(ipc.IpcErrorPortInUse, "ws_server_tls_cert: %w", err) }
  case "ws_server_tls_key":
      b, err := device.wsBinder(); if err != nil { return err }
      b.SetServerKeyPath(value)
      if err := device.BindUpdate(); err != nil { return ipcErrorf(ipc.IpcErrorPortInUse, "ws_server_tls_key: %w", err) }
  case "ws_server_bearer":
      b, err := device.wsBinder(); if err != nil { return err }
      device.log.Verbosef("UAPI: Updating ws_server_bearer") // key name only, never the value
      b.SetServerBearer(value)
  case "ws_trusted_proxies":
      b, err := device.wsBinder(); if err != nil { return err }
      prefixes, err := parseCIDRList(value); if err != nil { return ipcErrorf(ipc.IpcErrorInvalid, "ws_trusted_proxies: %w", err) }
      b.SetTrustedProxies(prefixes)
  ```

### Task 5.3 — `get=1` round-trip `[ ]`

**Actions:**
- `[ ]` **add** the round-trip reporter surface the get code below uses: in `conn/ws_endpoint.go` add `(*WSEndpoint) WSPeerKVs() []string` returning the `key=value` lines for a dialing endpoint (`ws_url`, `wstunnel_target`, `ws_bearer`, `ws_mask`, `ws_tls_ca`, `ws_tls_cert`, `ws_tls_key`, `ws_tls_insecure`, `ws_ping_interval`, `ws_backoff_min`, `ws_backoff_max`), omitting empty/zero values, in a stable order; in `device/uapi.go` declare the consumer-side interfaces `wsPeerReporter interface{ WSPeerKVs() []string }` and `wsServerReporter interface{ WSServerTLSPaths() (string, string); WSServerBearer() string; WSTrustedProxies() []netip.Prefix }` (satisfied by `*WSEndpoint` and the bind respectively, forwarded by the multiplex bind).
- `[ ]` **modify** `device/uapi.go` `IpcGetOperation`: emit `transport=<kind>` for **every** peer from the persisted `peer.transport` (NOT derived from the endpoint type — an endpoint-less UDP or inbound-WS peer has no endpoint to derive from); after `endpoint=` (emitted only when an endpoint is set), emit the per-peer `ws_*` keys for dialing `*WSEndpoint`s via a small reporter interface on `*WSEndpoint`; at device level, emit `ws_server_tls_cert`/`ws_server_tls_key` (paths), `ws_server_bearer`, `ws_trusted_proxies` alongside `ws_listen`, read from the bind via the device get reporters (`WSServerTLSPaths`/`WSServerBearer`/`WSTrustedProxies`, forwarded by the multiplex bind). `endpoint=` for a dialing WS peer is the resolved `dialTarget` ip:port.
  ```go
  // device level, after ws_listen=:
  if r, ok := device.net.bind.(wsServerReporter); ok {
      if cert, key := r.WSServerTLSPaths(); cert != "" { sendf("ws_server_tls_cert=%s", cert); sendf("ws_server_tls_key=%s", key) }
      if bearer := r.WSServerBearer(); bearer != "" { sendf("ws_server_bearer=%s", bearer) } // value emitted, never logged
      for _, p := range r.WSTrustedProxies() { sendf("ws_trusted_proxies=%s", p.String()) }
  }
  // per peer, first line of each peer block:
  sendf("transport=%s", peer.transport) // persisted; every peer, incl. endpoint-less
  // ...after endpoint= (only if set)...
  if wc, ok := peer.endpoint.val.(wsPeerReporter); ok { // dialing *WSEndpoint
      for _, kv := range wc.WSPeerKVs() { sendf("%s", kv) } // ws_url, wstunnel_target, ws_bearer, ws_mask, ws_tls_*, ws_ping_interval, ws_backoff_*
  }
  ```
- `[ ]` **remove** the now-obsolete `wsEndpointConfig` interface (`device/uapi.go:58-60`) and the `WSEndpoint.WSConfig` method (`conn/ws_endpoint.go`) — replaced by the per-peer `ws_*` reporter above. Required because US2 renames the fields `WSConfig` reads (`WSEndpoint.url`→`wsURL`, etc.), so leaving `WSConfig` is a compile break; and the unexported `wsEndpointConfig` interface would then be unused (`.golangci.yml` `unused`). Removal authorised by this plan's approval.

### Task 5.4 — Tests `[ ]`

| Test (file) | Verifies | Setup notes |
|---|---|---|
| `TestUAPI_Set_TransportMandatoryAtCreation` (`device/uapi_ws_test.go`) | creating a peer with no `transport` line is rejected; `udp`/`websocket`/`wstunnel` accepted; invalid value rejected | table via `IpcSet` reader |
| `TestUAPI_Set_IncrementalUpdateKeepsTransport` (`device/uapi_ws_test.go`) | updating an existing peer with NO `transport` line keeps the persisted transport (not rejected) — BOTH the `allowed_ip`-only case AND a dialing WS peer that omits `transport` but re-sends `ws_url`+`endpoint` (rebuilds via the persisted enum) | create then update, two sub-cases |
| `TestUAPI_Set_EndpointIsPlainIPPort` (`device/uapi_ws_test.go`) | `endpoint=ip:port` + `transport=websocket` + `ws_url=…` builds a `*WSEndpoint` dialing that ip:port | assert endpoint kind + dialTarget |
| `TestUAPI_Set_InboundWSPeer_NoURL` (`device/uapi_ws_test.go`) | `transport=websocket` with NO `ws_url`/`endpoint` is accepted (inbound peer; no dial endpoint built) | assert peer created, endpoint unset |
| `TestUAPI_Set_Validation` (`device/uapi_ws_test.go`) | `ws_*` rejected for `transport=udp`; dialing WS peer (`ws_url` set) requires `endpoint`; `wstunnel_target` requires `transport=wstunnel` + `ws_url` | table |
| `TestUAPI_Get_RoundTrip_AllTransports` (`device/uapi_ws_test.go`) | `get` emits `transport=` for every peer (udp, websocket, wstunnel, AND an endpoint-less inbound peer) from the persisted value, and round-trips every per-peer + device key; re-`set` of the dump reproduces identical state; `ws_bearer` echoed | build a device with dialing peers of each transport + one endpoint-less peer + device server keys |
| `TestUAPI_Get_NeverLogsSecrets` (`device/uapi_ws_test.go`) | key material, per-peer `ws_bearer`, AND device-level `ws_server_bearer` never appear in logs | capture logger output across set + get |

**DoD:** `[ ]` `transport` mandatory at creation + persisted, endpoint-as-ip:port, `ws_url` optional (inbound peers), full per-peer + device round-trip, `ws_mode` gone; tests written (execution deferred to US9).

---

## User Story 6 — Daemon wiring + `WG_WS_*` env retirement `[ ]`

**Why:** The daemon must build the multiplexing bind and stop reading the retired `WG_WS_*` env; the WS path monitor stays.

**Acceptance criteria:**
- `[ ]` `main.go` builds the multiplexing bind (all WS config now arrives via UAPI, not env).
- `[ ]` `WG_TRANSPORT`, `WG_WS_ROLE`, `WG_WS_MASK`, `WG_WS_TLS_*`, `WG_WS_BEARER`, `WG_WS_PING_INTERVAL`, `WG_WS_TRUSTED_PROXIES` are removed from `main.go`; `WG_METRICS_LISTEN` stays.
- `[ ]` The `WSPathMonitor` still drives `BindUpdate` on network change.

### Task 6.1 — daemon entry points `[ ]`

`buildWSOptionsFromEnv` lives in `main_ws.go` (no build tag → all GOOS), and BOTH `main.go` and `main_windows.go` call it + `conn.NewBindForTransport`. All three MUST be updated together or the windows build breaks.

**Actions:**
- `[ ]` **modify** `main_ws.go`: remove `buildWSOptionsFromEnv` and every `WG_TRANSPORT`/`WG_WS_*` read. **KEEP** `startMetrics` and `wsMetricsSnapshot` (and `WG_METRICS_LISTEN`). Add a `newDaemonBind(logger *device.Logger) (conn.Bind, error)` helper (no build tag → shared by both entry points) — the single, determinate construction path.
  ```go
  func newDaemonBind(logger *device.Logger) (conn.Bind, error) {
      return conn.NewMultiplexBind(
          conn.WithWSLogger(conn.Logger{Verbosef: logger.Verbosef, Errorf: logger.Errorf}),
          // conn.WithWSProtect(...) only where a protect callback exists (e.g. android integration).
      )
  }
  ```
- `[ ]` **modify** `main.go`: drop the `WG_TRANSPORT`/`WG_WS_*`/`buildWSOptionsFromEnv` reads; construct the bind via `newDaemonBind(logger)`. Keep `startMetrics`. Keep the `WSPathMonitor` block but replace the removed `if transport == "ws"` guard: the monitor always starts, and its `onChange` callback calls `device.BindUpdate()` ONLY when the bind reports WS is in use — `func() { if b, ok := bind.(interface{ WSInUse() bool }); ok && b.WSInUse() { _ = device.BindUpdate() } }`. This preserves the "UDP data path unchanged" invariant (a pure-UDP daemon's bind is never reopened on a network change, exactly as today), while WS still gets its roaming refresh.
- `[ ]` **modify** `main_windows.go`: construct the bind via `newDaemonBind(logger)` (no env), preserving the rest of the windows startup.
- `[ ]` **modify** `conn/ws_config.go`: delete the now-unused `WithWS*` options for retired client/env settings; keep `WithWSLogger`, `WithWSProtect`. Keep the `wsDefault*` timing constants (now applied per-peer, Task 3.1).

### Task 6.2 — Migrate the e2e harness + tests, add mixed-peer coverage `[ ]`

**Actions:**
- `[ ]` **modify** `tests/e2e/e2e_test.go` + `tests/e2e/harness_test.go` + `tests/e2e/tls_test.go`: migrate EVERY existing case (UDP, WebSocket, Wstunnel, WstunnelMasked) off the retired env (`WG_TRANSPORT`, `WG_WS_ROLE`, `WG_WS_TLS_*`, `WG_WS_MASK`) and off the old UAPI model (`endpoint=wss://…`, `ws_mode=…`) to the new model: `startDaemon` with no WS env; per-peer `transport=udp|websocket|wstunnel`, `endpoint=ip:port`, `ws_url=…`, per-peer `ws_*` keys, and device-level `ws_listen`/`ws_server_tls_cert`/`ws_server_tls_key`/`ws_server_bearer` via UAPI. Otherwise every case (including UDP, which now needs a `transport=` line) fails.

**Tests:**

| Test (file) | Verifies | Setup notes |
|---|---|---|
| `TestNewMultiplexBind_Defaults` (`conn/ws_multiplex_test.go`) | constructed with logger/protect only; no env read | assert bind is usable for both transports |
| e2e `TestE2E_MixedPeers` (`tests/e2e/e2e_test.go`) | one device with a UDP peer AND a WS peer simultaneously passes traffic to both | netns: two servers (one UDP, one WS/TLS), one client with both peers |
| e2e `TestE2E_WebSocket_FullTunnel` / `TestE2E_Wstunnel_FullTunnel` (`tests/e2e/e2e_test.go`) | WS + wstunnel tunnel passes traffic under `fwmark` + `ip -4 rule add not fwmark <t> table <t>` + default route in table `<t>` (proves US1's fwmark fix) | netns client on the final UAPI model; set `fwmark=<t>` via UAPI after `ifup`; install rule/route; `ping` must succeed (fails without US1, passes with it) |

**DoD:** `[ ]` no `WG_WS_*`/`WG_TRANSPORT` reads remain in the daemon or the e2e harness; all migrated + new e2e cases (incl. mixed-peer and the WS/wstunnel full-tunnel cases) are written (executed in US9).

### Task 6.3 — Migrate ALL peer-creating UAPI callers (tests + examples) to the new model `[ ]`

**Why:** Two universal changes ripple beyond WS: (a) US2–US6 remove/rename exported symbols (`WSRole`, `WithWSRole`, `WithWSMask`, `WithWSClientTLS`, `WithWSPingInterval`, `WithWSTrustedProxies`, `NewBindForTransport`, `WSConfig`, the positional `ParseWSPeerEndpoint`) and `ws_mode`; (b) `transport` is MANDATORY at peer creation for EVERY bind type, so ANY `IpcSet` that creates a peer without a `transport=` line now fails (`peer missing mandatory transport`) — including UDP-only and general tests/examples. Every affected caller must be migrated or `make test` fails at US9. Gates run only in US9; only the FINAL state must compile and pass.

**Actions:**
- `[ ]` **modify** the shared `conn` test helpers to the new per-peer/multiplex API + UAPI model: `conn/ws_testhelpers_test.go` (`newWSDevicePair`), the `newWSClientDevice` helper (in `conn/wstunnel_relay_test.go`), and any `mockWSBind`/helpers — drop `WithWSRole`/`WithWSClientTLS`/`WithWSPingInterval`/`WithWSListenURL`/`WithWSServerBearer` usage, configure via the new device-level setters + per-peer `transport=`/`endpoint=ip:port`/`ws_url=`/`ws_*` UAPI keys (no `ws_mode`).
- `[ ]` **modify** the WS-dependent tests to match: `conn/ws_masking_test.go`, `conn/ws_tunnel_test.go`, `conn/wstunnel_relay_test.go`, `conn/ws_server_test.go`, `conn/ws_bind_test.go`, `conn/ws_endpoint_internal_test.go`, `conn/ws_internal_test.go` (its `TestWSUpgrade*` cases build `&WSEndpoint{url: …}` and call `wsUpgradeRequest` — migrate to `wsURL`/the new dial-config path), and `device/uapi_ws_test.go`. In `device/uapi_ws_test.go`, `mockWSBind` MUST satisfy the extended `conn.WebSocketBinder`: change `ParseWSPeerEndpoint` to the new `WSPeerConfig` signature AND add `SetServerCertPath`/`SetServerKeyPath`/`SetServerBearer`/`SetTrustedProxies` (and, if the get reporters are part of the asserted interface, `WSServerTLSPaths`/`WSServerBearer`/`WSTrustedProxies`); replace `ws_mode=` strings with `transport=`; drop removed options.
- `[ ]` **modify** the NON-WS peer-creating UAPI callers to add `transport=udp` at each peer creation (mandatory-transport impact): `device/device_test.go` (`genConfigs`/`uapiCfg`), `device/stats_test.go`, `conn/udp_tunnel_test.go`, and the netstack embedding examples `tun/netstack/examples/{ping_client,http_client,http_server}.go` (`dev.IpcSet(...)` configs). Sweep for any other `IpcSet`/`IpcSetOperation` caller creating a peer without a `transport=` line.
- `[ ]` **delete** tests of removed constructs: `TestNewBindForTransport` (`conn/ws_bind_test.go`), `TestWSEndpoint_WSConfig` (`conn/ws_endpoint_internal_test.go`, superseded by `TestWSEndpoint_DstToString_ClientResolved` in US2), and the old-signature `TestWebSocketBind_ParseWSPeerEndpoint`. Deletion of these obsolete tests is authorised by this plan's approval.

**DoD:** `[ ]` no `conn`/`device` test references a removed/renamed symbol or `ws_mode`; every peer-creating `IpcSet` (tests + netstack examples) sends `transport=`; the shared helpers use the new API (compile/execution in US9).

---

## User Story 7 — Remove the darwin `IP_BOUND_IF` pin `[ ]`

**Why:** With `endpoint=ip:port`, `wg-quick` host-routes the WS transport on darwin; the pin is redundant and harmful under full-tunnel (`defaultEgressIfIndex()` can resolve to the `utun`, and `IP_BOUND_IF` overrides the route). Sequenced last among code changes; macOS validation is Manual QA coordinated with the tools change.

**Acceptance criteria:**
- `[ ]` The darwin dialControl no longer pins to an egress interface; it only invokes `protect` (matching the non-mark default) — darwin `SetMark`/mark stays a no-op (parity with UDP).
- `[ ]` The egress-detection code and its test seam are removed.

### Task 7.1 — Remove pin + egress detection `[ ]`

**Actions:**
- `[ ]` **modify** `conn/ws_pinning_darwin.go`: replace the `IP_BOUND_IF`/`IPV6_BOUND_IF` body with a protect-only `dialControl` (identical shape to `ws_pinning_default.go`). Remove the `egressIfIndex`/`wsIsLoopback`/`wsIsIPv6` usage from the dial path.
- `[ ]` **remove** `conn/ws_iface_darwin.go` and `conn/ws_iface_darwin_test.go` (egress detection + seam) — no other caller remains after the pin is gone (verify via `git grep egressIfIndex`). Removal of these files is authorised by this plan's approval (agent.md §2 code-integrity: not a failure-hiding deletion, a designed removal).
- `[ ]` **modify** `conn/ws_pinning_darwin_test.go`: drop the pin-specific assertions; keep/rework only the `protect` invocation test (or fold into the default test).

**DoD:** `[ ]` `git grep -n "IP_BOUND_IF\|egressIfIndex" conn/` returns nothing; the darwin `dialControl` is protect-only; the egress-detection files and their tests are removed (build/test execution deferred to US9).

### Task 7.2 — Manual QA note `[ ]`

- `[ ]` Record in `docs/WGQUICK_INTEGRATION.md` (US8) a **Manual QA (macOS)** section: full-tunnel over WS/wstunnel requires the wireguard-tools change (host-route `endpoint=ip:port`); steps to verify on a Mac (bring up `0.0.0.0/0`, confirm handshake + traffic, confirm the transport socket egresses the physical interface).

---

## User Story 8 — Documentation `[ ]`

**Why:** Docs and the project ruleset must reflect the new per-peer model, transport contract, mixed peers, multiplexing bind, and the retired env/URL-in-endpoint model.

**Acceptance criteria:**
- `[ ]` `docs/PROJECT.md`, `docs/ARCHITECTURE.md`, `docs/CONFIGURATION.md` updated; `docs/ANDROID_INTEGRATION.md` updated; new `docs/WGQUICK_INTEGRATION.md` created; `.claude/rules/project.md` invariant updated.
- `[ ]` Mermaid charts are authored/updated where needed; their validation (`make mermaid-check`) runs in US9, NOT per-task.

### Task 8.1 — Canonical docs `[ ]`

**Actions:**
- `[ ]` **modify** `docs/PROJECT.md`: per-peer `transport` + `endpoint=ip:port` + `ws_url` + per-peer/device key tables; retire `WG_WS_*`/`WG_TRANSPORT`/`WS_ROLE`; mixed peers; multiplexing bind; server settings via UAPI.
- `[ ]` **modify** `docs/ARCHITECTURE.md`: multiplexing bind topology, per-peer WS dial config, simultaneous client+server, fwmark cooperation, darwin off-tun via `wg-quick`. Update/add Mermaid charts.
- `[ ]` **modify** `docs/CONFIGURATION.md`: full UAPI key reference (per-peer + device), `get`/`set` round-trip, examples for udp/websocket/wstunnel and mixed.
- `[ ]` **modify** `docs/ANDROID_INTEGRATION.md`: required per-peer keys, how the app supplies them, what changed (no URL-in-endpoint, no env).
- `[ ]` **create** `docs/WGQUICK_INTEGRATION.md`: which parameters `wg-quick`/tools must emit (per-peer `Transport`, `endpoint=ip:port`, `ws_url`, `ws_*`, device `ws_listen`/`ws_server_*`/`ws_trusted_proxies`), how off-tun works (Linux fwmark cooperation; darwin/BSD host-route `endpoint=ip:port`), the Manual QA (macOS) section (US7.2).
- `[ ]` **modify** `.claude/rules/project.md`: change the "UAPI must stay compatible with `wg(8)`" invariant to "UAPI is a stable contract for the fork's own tooling; wire-protocol interop with standard WireGuard remains sacred"; refresh the WebSocket transport row and commit scopes if needed. Keep CONCISE; reference canonical docs.

**DoD:** `[ ]` docs consistent with the code; Mermaid charts authored/updated (validation deferred to US9).

---

## User Story 9 — Ground-up verification (LAST) `[ ]`

**Why:** Verify the entire plan end-to-end from the ground up.

### Task 9.1 — Quality gates `[ ]`

**Actions:**
- `[ ]` Run the quality gates via project commands: `make lint`, `make vet`, `go build ./...` (and a cross-`GOOS` build check for linux/darwin/windows/freebsd/openbsd), `make test` (`-race`), `make test-e2e` (Linux+root, with `WSTUNNEL_BIN`), `make tidy` (no `go.mod`/`go.sum` diff), `make vulncheck`, `make mermaid-check`. Capture each long run via `tee` to `/tmp/wireguard-go-<gate>.log`.

**DoD:** `[ ]` all quality gates pass on the final code.

### Task 9.2 — Live docker integration test against the real wstunnel server `[ ]`

**Why:** The end goal is real-world full-tunnel over wstunnel. Before the code review, prove the implementation works against the user's LIVE WireGuard server behind wstunnel, both split and full tunnel, from inside a docker container (isolated netns so host macOS networking is untouched).

**Actions:**
- `[ ]` Using the user's real config (private key NEVER printed/logged), run inside a docker container: bring up the WS/wstunnel client tunnel to the live server and verify connectivity (handshake + ping/curl through the tunnel) with **split-tunnel** (a narrow `allowed_ip`).
- `[ ]` Repeat with **full-tunnel** (`AllowedIPs=0.0.0.0/0`) including the `fwmark` + `ip rule not fwmark` + default-route setup (via the modified `wg-quick` or an equivalent harness), and verify traffic flows and the transport socket escapes the tunnel (no self-loop).
- `[ ]` Capture each run via `tee` to `/tmp/wireguard-go-live-<split|full>.log`.

**DoD:** `[ ]` both split and full-tunnel live-server runs succeed inside docker; logs captured; no private key emitted anywhere.

### Task 9.3 — Ground-up double-check (LAST) `[ ]`

**Why:** `development_pipeline.md` §3 requires the final task to double-check EVERYTHING implemented, from the ground up. Runs after the gates (9.1) and the live docker test (9.2).

**Actions:**
- `[ ]` Re-read this plan from disk and confirm every user story's acceptance criteria and checkmarks are satisfied; record any deviation in `## Deviations`.
- `[ ]` Confirm the invariants from the ground up: UDP data path unchanged (Windows keeps `WinRingBind`); wire protocol untouched; no secret/key material logged; cross-GOOS build for linux/darwin/windows/freebsd/openbsd; `ws_mode`/`WS_ROLE`/`WG_WS_*`/URL-in-endpoint fully removed; `transport` mandatory at creation + persisted; `endpoint=ip:port` everywhere; `ws_url` optional (inbound peers); mixed peers + simultaneous client+server working; the fwmark live re-mark + dial/accept marking in place.
- `[ ]` Validate ALL touched/added Mermaid charts (the `docs/ARCHITECTURE.md` charts changed in US8) per `development_pipeline.md` §9 — run `make mermaid-check` and confirm every chart passes (this is the §3-mandated Mermaid step inside the final ground-up task).
- `[ ]` Confirm the Manual QA (macOS) note + Release sequencing are present and accurate (US7.2/US8), and that Task 9.1 gates + Task 9.2 live-docker runs are green.

**DoD:** `[ ]` every checkbox in this plan is ticked; all invariants confirmed; all touched Mermaid charts validate; deviations (if any) recorded; the plan is verified end-to-end from the ground up.

---

## Release sequencing (SACRED order — do NOT reorder)

This overrides nothing in `development_pipeline.md` except to INSERT one explicit, user-directed manual gate immediately before the PR. The order is:

1. Implement US1→US8 end to end.
2. **US9 verification:** quality gates (lint/vet/build/`-race` unit/tidy/vulncheck/mermaid) + Linux netns e2e (incl. mixed peers + WS/wstunnel full-tunnel) + the **live docker integration test** (Task 9.2, split AND full tunnel against the real server).
3. **Stage 4 post-implementation code review** (fresh `code-reviewer`, loop to ZERO findings; re-run quality gates if any code changed).
4. **macOS real-device Manual QA — LITERALLY THE LAST STEP BEFORE THE PR.** After steps 2–3 are all green: **STOP and notify the user.** The user runs (or drives) the real macOS full-tunnel (`0.0.0.0/0`) test over WS/wstunnel — this may require the user to switch networks. Do NOT open the PR until the user CONFIRMS the macOS test passes.
5. Open the PR and report the URL.

**This macOS manual gate is mandatory, is the last thing before the PR, and requires an explicit user confirmation to proceed.**

---

## Deviations

_(none yet — record here during implementation per agent.md §2: task/action reference + what changed + why.)_
