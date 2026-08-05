<!-- SACRED DOCUMENT — Edit ONLY per agent.md §2 plan-file rules: plan-review fixes, checkmarks, recorded implementation deviations, and code-review re-alignment. -->
<!-- You MUST NEVER delete this file or alter files outside this plan's scope. -->
<!-- Plans in docs/plans/ are PERMANENT artifacts. There are ZERO exceptions. -->

# Plan 1 — WebSocket Transport (client + server, wstunnel interop, metrics, mobile, packaging)

Executes `docs/WORK_PLAN.md` (P1–P10) end to end. Read `docs/WORK_PLAN.md`, `docs/ARCHITECTURE.md`,
`docs/PROJECT.md`, and `docs/ANDROID_INTEGRATION.md` first — this plan does NOT repeat their rationale;
it cites decisions as `D1`…`D19` and phases as `P1`…`P10`.

Invariants (WORK_PLAN §6) bind every task: wire protocol untouched; single bind per device; all
transport logic behind `conn.Bind`/`conn.Endpoint` (device core stays transport-agnostic, extended
ONLY via optional interfaces the core type-asserts, exactly like the existing `conn.PeekLookAtSocketFd`
at [conn/conn.go:69](../../conn/conn.go#L69)); no secrets in logs or `IpcGet`; every GOOS keeps
compiling; `-race` everywhere.

## Versions to pin (verified this session)

| Dependency / tool | Version | Source |
|---|---|---|
| `github.com/coder/websocket` | `v1.8.15` | proxy.golang.org (`@latest`) |
| `github.com/golang-jwt/jwt/v5` | `v5.3.1` | proxy.golang.org (`@latest`) |
| `github.com/google/uuid` | `v1.6.0` | proxy.golang.org (`@latest`) |
| `github.com/prometheus/client_golang` | `v1.24.1` | proxy.golang.org (`@latest`) |
| `actions/checkout` | `v7.0.1` | `gh api repos/actions/checkout/releases/latest` |
| `actions/setup-go` | `v7.0.0` | `gh api …` |
| `goreleaser/goreleaser-action` | `v7.2.3` | `gh api …` |
| `golangci/golangci-lint-action` | `v9.3.0` | `gh api …` |
| `docker/login-action` | `v4.6.0` | `gh api …` |
| `docker/setup-qemu-action` | `v4.2.0` | `gh api …` |
| `docker/setup-buildx-action` | `v4.2.0` | `gh api …` |
| goreleaser CLI | `v2.17.1` | `project.md` |

The wstunnel HS256 JWT is built with `github.com/golang-jwt/jwt/v5` and the UUIDv4 with
`github.com/google/uuid` (both verified latest). The wstunnel server does not verify the signature
(D16), so any HS256 secret works — but the token MUST still be a well-formed HS256 JWT, which the
library guarantees.

---

## [ ] US1 — Foundation: endpoint type, WS config, transport switch, UAPI keys (P1)

**Why:** Establish the `conn`-side WS types, the process-level transport switch, and the additive UAPI
keys so a device can be started on the (not-yet-functional) WS bind and round-trip WS config. Depends
on: none.

**Acceptance criteria:**
- [ ] `WG_TRANSPORT=ws` selects the WS bind at startup; unset/`udp` keeps `conn.NewDefaultBind()`.
- [ ] `conn.NewWebSocketBind(...)` constructs a bind via functional options (programmatic, for mobile).
- [ ] `WSEndpoint` implements `conn.Endpoint`; `ws`/`wss` URLs round-trip through `DstToString`.
- [ ] UAPI accepts additive keys (`ws_listen` device; `ws_mode`, `ws_target`, `ws_bearer`, ws-URL
      `endpoint` peer); every other unknown key is still rejected; `ws_bearer` is NEVER echoed/logged.
- [ ] All GOOS targets compile; `go mod tidy` clean; `govulncheck` clean.

### [ ] Task 1.1 — Add the WebSocket library
- [ ] **Action 1.1.1** — modify `go.mod`: add `require github.com/coder/websocket v1.8.15`; run
  `go mod tidy`; commit `go.mod` + `go.sum`. (`deps` scope.)

### [ ] Task 1.2 — `conn` config, endpoint, and optional interfaces
- [ ] **Action 1.2.1** — create `conn/ws_config.go`: role/mode types, config struct, functional
  options, and the small logger type. `conn` MUST NOT import `device`. `device.Logger`
  ([device/logger.go:18-21](../../device/logger.go#L18)) exposes `Verbosef`/`Errorf` as **func-typed
  fields, NOT methods**, so a method interface would NOT be satisfied — model the `conn` logger as a
  struct of func fields and let the daemon populate it from `*device.Logger`'s fields.

```go
package conn

import (
	"crypto/tls"
	"net/netip"
	"time"
)

type WSRole int

const (
	WSRoleClient WSRole = iota
	WSRoleServer
)

// Logger is the minimal logging surface the WS bind needs, modeled as func fields
// (NOT an interface) to mirror device.Logger, whose Verbosef/Errorf are func fields,
// not methods. conn does not import device; the daemon builds this from *device.Logger:
//   conn.Logger{Verbosef: l.Verbosef, Errorf: l.Errorf}
// A nil field means that level is silent; callers MUST nil-check before invoking.
type Logger struct {
	Verbosef func(format string, args ...any)
	Errorf   func(format string, args ...any)
}

// nil-safe internal accessors used throughout the WS code.
func (l Logger) verbosef(f string, a ...any) { if l.Verbosef != nil { l.Verbosef(f, a...) } }
func (l Logger) errorf(f string, a ...any)   { if l.Errorf != nil { l.Errorf(f, a...) } }

const (
	wsDefaultPingInterval = 25 * time.Second
	wsDefaultBackoffMin   = 500 * time.Millisecond
	wsDefaultBackoffMax   = 30 * time.Second
	// wsReadLimit caps a single inbound WS message. 1<<16 covers the largest
	// device receive buffer (MaxSegmentSize) on every platform; the exact
	// per-message guard is len(callerBuffer) at delivery time.
	wsReadLimit = 1 << 16
)

type wsConfig struct {
	role           WSRole
	listenURL      string
	tlsClient      *tls.Config
	tlsServer      *tls.Config
	serverBearer   string // server role: expected Bearer (coarse gate); empty = gate off. NEVER logged.
	pingInterval   time.Duration
	backoffMin     time.Duration
	backoffMax     time.Duration
	trustedProxies []netip.Prefix
	protect        func(fd int)
	logger         Logger
}

type WSOption func(*wsConfig) error

func WithWSRole(r WSRole) WSOption            { return func(c *wsConfig) error { c.role = r; return nil } }
func WithWSClientTLS(t *tls.Config) WSOption  { return func(c *wsConfig) error { c.tlsClient = t; return nil } }
func WithWSServerTLS(t *tls.Config) WSOption  { return func(c *wsConfig) error { c.tlsServer = t; return nil } }
func WithWSServerBearer(tok string) WSOption  { return func(c *wsConfig) error { c.serverBearer = tok; return nil } }
func WithWSListenURL(u string) WSOption       { return func(c *wsConfig) error { c.listenURL = u; return nil } }
func WithWSPingInterval(d time.Duration) WSOption { return func(c *wsConfig) error { c.pingInterval = d; return nil } }
func WithWSTrustedProxies(p []netip.Prefix) WSOption { return func(c *wsConfig) error { c.trustedProxies = p; return nil } }
func WithWSProtect(fn func(fd int)) WSOption  { return func(c *wsConfig) error { c.protect = fn; return nil } }
func WithWSLogger(l Logger) WSOption          { return func(c *wsConfig) error { c.logger = l; return nil } }
```

- [ ] **Action 1.2.2** — create `conn/ws_endpoint.go`: `WSEndpoint` implementing `conn.Endpoint`.
  Client role carries the canonical dial URL plus dialect fields; server role carries the accepted
  client's `netip.AddrPort` and the live-connection id. `DstToString` returns the plain URL (client)
  or `ip:port` (server) — NEVER the bearer. `DstIP`/`DstToBytes` derive from `dst` (server: the
  remote/XFF address, feeding rate-limiter + MAC2; client: the resolved dial IP, best-effort).

```go
package conn

import "net/netip"

type wsDialect int

const (
	wsDialectStandard wsDialect = iota
	wsDialectWstunnel
)

type WSEndpoint struct {
	url     string         // client: canonical ws(s):// URL, echoed by IpcGet
	dialect wsDialect      // client only
	target  string         // client, wstunnel mode: real WG "host:port" (JWT r/rp)
	bearer  string         // client: optional bearer; NEVER echoed or logged
	dst     netip.AddrPort // server: client remote (or XFF) addr; client: resolved dial addr
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
```

- [ ] **Action 1.2.3** — create `conn/ws_bind.go`: `WebSocketBind` struct + `NewWebSocketBind`, the
  optional interfaces the device type-asserts, and the FULL `conn.Bind` method set so the interface is
  satisfied and the device compiles/runs after US1. `ParseEndpoint` parses a standard-mode `ws(s)://`
  URL; `BatchSize()==1`; `SetMark` stores the mark (applied in US5); `SetWSListen` stores the listen
  URL; and `Open`/`Close`/`Send` are **compiling stubs** (Open returns one `ReceiveFunc` that blocks
  until `Close`, Send returns a "not yet functional" error) — US2 (client) and US6 (server) REPLACE
  these three method bodies with the real implementations. `WebSocketBind` MUST NOT implement
  `conn.PeekLookAtSocketFd` (D-P9).

```go
package conn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// All fields (client + server) are declared here so the canonical Close (added
// next) type-checks; the client/server methods that populate them come later.
// The metrics field is added when wsMetricsState is introduced.
type WebSocketBind struct {
	cfg  wsConfig
	mark atomic.Uint32 // SO_MARK, set via SetMark, read in dialControl (race-free)

	mu        sync.Mutex
	closed    bool
	inbound   chan wsInbound // shared receive queue drained by ReceiveFuncs; NEVER closed
	done      chan struct{}  // closed by Close to unblock ReceiveFuncs (nil while not open)
	ctx       context.Context
	ctxCancel context.CancelFunc
	readWG    sync.WaitGroup

	// client role: conns + dialBackoff are mutated under b.mu; dialM serialises the
	// dial path (so two concurrent Sends to a new endpoint dial once).
	conns       map[string]*wsClientConn
	dialM       sync.Mutex
	dialBackoff map[string]wsBackoff

	// server role
	srv        *http.Server
	sconns     map[uint64]*wsServerConn
	nextConnID uint64
}

type wsBackoff struct {
	until time.Time
	d     time.Duration
}

type wsInbound struct {
	data []byte
	ep   *WSEndpoint
}

type wsClientConn struct {
	conn   *websocket.Conn
	writeM sync.Mutex
	ep     *WSEndpoint
	ctx    context.Context    // per-connection; derived from the open ctx, cancelled on drop/close
	cancel context.CancelFunc
}

type wsServerConn struct {
	conn   *websocket.Conn
	writeM sync.Mutex
	id     uint64
	ctx    context.Context // captured at accept from the open ctx
}

// WebSocketBinder is type-asserted by the device UAPI handler to build WS peer
// endpoints and set the server listen URL from the additive UAPI keys, mirroring
// how conn.PeekLookAtSocketFd is type-asserted elsewhere. Keeps WS specifics out
// of the device core.
type WebSocketBinder interface {
	SetWSListen(rawURL string) error
	ParseWSPeerEndpoint(rawURL, mode, target, bearer string) (Endpoint, error)
}

var (
	_ Bind            = (*WebSocketBind)(nil)
	_ WebSocketBinder = (*WebSocketBind)(nil)
)

func NewWebSocketBind(opts ...WSOption) (*WebSocketBind, error) {
	cfg := wsConfig{
		pingInterval: wsDefaultPingInterval,
		backoffMin:   wsDefaultBackoffMin,
		backoffMax:   wsDefaultBackoffMax,
	}
	for _, o := range opts {
		if err := o(&cfg); err != nil {
			return nil, err
		}
	}
	return &WebSocketBind{cfg: cfg}, nil
}

func (b *WebSocketBind) BatchSize() int { return 1 }

func (b *WebSocketBind) ParseEndpoint(s string) (Endpoint, error) {
	return b.ParseWSPeerEndpoint(s, "standard", "", "")
}

func (b *WebSocketBind) ParseWSPeerEndpoint(rawURL, mode, target, bearer string) (Endpoint, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid websocket endpoint %q: %w", rawURL, err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, fmt.Errorf("invalid websocket endpoint %q: scheme must be ws or wss", rawURL)
	}
	e := &WSEndpoint{url: rawURL, target: target, bearer: bearer}
	switch mode {
	case "", "standard":
		e.dialect = wsDialectStandard
	case "wstunnel":
		e.dialect = wsDialectWstunnel
		if target == "" {
			return nil, fmt.Errorf("ws_mode=wstunnel requires ws_target")
		}
	default:
		return nil, fmt.Errorf("invalid ws_mode %q", mode)
	}
	return e, nil
}

func (b *WebSocketBind) SetMark(mark uint32) error { b.mark.Store(mark); return nil }

func (b *WebSocketBind) SetWSListen(rawURL string) error {
	if _, err := url.Parse(rawURL); err != nil {
		return fmt.Errorf("invalid ws_listen %q: %w", rawURL, err)
	}
	b.cfg.listenURL = rawURL
	return nil
}

// --- Compiling stubs, replaced by the real client/server implementations. ---

func (b *WebSocketBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done != nil {
		return nil, 0, ErrBindAlreadyOpen
	}
	done := make(chan struct{})
	b.done = done
	fn := func(bufs [][]byte, sizes []int, eps []Endpoint) (int, error) {
		<-done // captured local; no race with Close reassigning b.done
		return 0, net.ErrClosed
	}
	return []ReceiveFunc{fn}, port, nil
}

func (b *WebSocketBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done != nil {
		close(b.done)
		b.done = nil
	}
	return nil
}

func (b *WebSocketBind) Send(bufs [][]byte, ep Endpoint) error {
	return errors.New("websocket bind not yet functional")
}
```

  On the client, `WSEndpoint.dst` is left zero (advisory only — the client never runs the
  handshake rate-limiter or MAC2 cookie check, which are the sole consumers of `DstIP`/`DstToBytes`);
  no DNS pre-resolution helper is needed. `DstToString` round-trips the URL, which is what `IpcGet`
  emits.

### [ ] Task 1.3 — Transport switch in the daemon
- [ ] **Action 1.3.1** — create `conn/default_ws.go`.

```go
package conn

import "fmt"

// NewBindForTransport selects the bind at startup (keeps main thin and testable).
func NewBindForTransport(transport string, opts ...WSOption) (Bind, error) {
	switch transport {
	case "", "udp":
		return NewDefaultBind(), nil
	case "ws":
		return NewWebSocketBind(opts...)
	default:
		return nil, fmt.Errorf("invalid WG_TRANSPORT %q (want udp|ws)", transport)
	}
}
```
- [ ] **Action 1.3.2** — modify `main.go`: read process-level env (see table) and select the bind.

```go
// after logger is constructed, before device.NewDevice:
transport := os.Getenv("WG_TRANSPORT")
wsOpts, err := buildWSOptionsFromEnv(logger) // reads WG_WS_* env (role, TLS, ping, proxies)
if err != nil {
	logger.Errorf("invalid websocket configuration: %v", err)
	os.Exit(ExitSetupFailed)
}
bind, err := conn.NewBindForTransport(transport, wsOpts...)
if err != nil {
	logger.Errorf("invalid WG_TRANSPORT: %v", err)
	os.Exit(ExitSetupFailed)
}
device := device.NewDevice(tdev, bind, logger)
```

  `buildWSOptionsFromEnv(logger *device.Logger)` builds `WithWSLogger(conn.Logger{Verbosef:
  logger.Verbosef, Errorf: logger.Errorf})` (the daemon adapts `*device.Logger`'s func fields to the
  `conn.Logger` struct) and parses: `WG_WS_ROLE=client|server`
  (default client), `WG_WS_TLS_CERT`/`WG_WS_TLS_KEY` (server wss), `WG_WS_TLS_CA`/`WG_WS_TLS_SERVERNAME`/`WG_WS_TLS_INSECURE`
  (client wss; empty ⇒ system roots, D §4), `WG_WS_BEARER` (server role: the expected coarse-gate
  bearer → `WithWSServerBearer`; empty ⇒ gate off — the per-peer client bearer is the UAPI `ws_bearer`
  key, NOT this), `WG_WS_PING_INTERVAL`, `WG_WS_TRUSTED_PROXIES` (comma CIDRs). `WG_WS_BEARER` MUST
  NOT be logged. Mobile client TLS = system roots only (decided) ⇒ CA/servername optional.

```go
// main.go (or main_ws.go) — process-level WS config assembly.
func buildWSOptionsFromEnv(logger *device.Logger) ([]conn.WSOption, error) {
	opts := []conn.WSOption{
		conn.WithWSLogger(conn.Logger{Verbosef: logger.Verbosef, Errorf: logger.Errorf}),
	}
	role := conn.WSRoleClient
	if os.Getenv("WG_WS_ROLE") == "server" {
		role = conn.WSRoleServer
	}
	opts = append(opts, conn.WithWSRole(role))

	if cert, key := os.Getenv("WG_WS_TLS_CERT"), os.Getenv("WG_WS_TLS_KEY"); cert != "" && key != "" {
		crt, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("load server TLS keypair: %w", err)
		}
		opts = append(opts, conn.WithWSServerTLS(&tls.Config{Certificates: []tls.Certificate{crt}}))
	}

	ca, sni, insecure := os.Getenv("WG_WS_TLS_CA"), os.Getenv("WG_WS_TLS_SERVERNAME"), os.Getenv("WG_WS_TLS_INSECURE") == "1"
	if ca != "" || sni != "" || insecure {
		tc := &tls.Config{ServerName: sni, InsecureSkipVerify: insecure}
		if ca != "" {
			pem, err := os.ReadFile(ca)
			if err != nil {
				return nil, fmt.Errorf("read client CA: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("client CA %q: no certificates parsed", ca)
			}
			tc.RootCAs = pool
		}
		opts = append(opts, conn.WithWSClientTLS(tc))
	}

	if tok := os.Getenv("WG_WS_BEARER"); tok != "" {
		opts = append(opts, conn.WithWSServerBearer(tok))
	}
	if d := os.Getenv("WG_WS_PING_INTERVAL"); d != "" {
		iv, err := time.ParseDuration(d)
		if err != nil {
			return nil, fmt.Errorf("WG_WS_PING_INTERVAL: %w", err)
		}
		opts = append(opts, conn.WithWSPingInterval(iv))
	}
	if cidrs := os.Getenv("WG_WS_TRUSTED_PROXIES"); cidrs != "" {
		var prefixes []netip.Prefix
		for _, c := range strings.Split(cidrs, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(c))
			if err != nil {
				return nil, fmt.Errorf("WG_WS_TRUSTED_PROXIES %q: %w", c, err)
			}
			prefixes = append(prefixes, p)
		}
		opts = append(opts, conn.WithWSTrustedProxies(prefixes))
	}
	return opts, nil
}
```

  New `main.go` imports: `crypto/tls`, `crypto/x509`, `net/netip`, `strings`, `time` (plus existing
  `fmt`/`os`/`conn`/`device`). `InsecureSkipVerify` is set ONLY from the explicit `WG_WS_TLS_INSECURE=1`
  opt-in.
- [ ] **Action 1.3.3** — modify `main_windows.go`: same switch (Windows is a debug harness; keep it
  compiling and consistent — WS client is supported on Windows).

### [ ] Task 1.4 — Additive UAPI keys (device core, transport-agnostic)
- [ ] **Action 1.4.1** — modify `device/uapi.go` `handleDeviceLine`: add a `ws_listen` case that
  type-asserts `device.net.bind` to `conn.WebSocketBinder`, calls `SetWSListen(value)`, then
  `device.BindUpdate()`. If the bind is not a `WebSocketBinder`, return `IpcErrorInvalid`
  (`ws_listen requires the websocket transport`). Unknown keys still hit `default:` → rejected.
- [ ] **Action 1.4.2** — modify `device/uapi.go` `ipcSetPeer`: add fields `wsEndpointURL, wsMode,
  wsTarget, wsBearer string`. CRITICAL: `ipcSetPeer` is allocated ONCE and REUSED for every peer in a
  `set=1` op ([device/uapi.go:150](../../device/uapi.go#L150)), and `handlePublicKeyLine`
  ([device/uapi.go:274](../../device/uapi.go#L274)) resets only `Peer`/`dummy`/`created`. To stop peer
  N inheriting peer N-1's WS keys, RESET the four WS fields to `""` at the start of
  `handlePublicKeyLine` (when a new peer begins). In `handlePeerLine`:
  - `endpoint`: if `value` scheme is `ws`/`wss`, store `peer.wsEndpointURL = value` and DEFER (do
    not build yet — `ws_mode`/`ws_target`/`ws_bearer` may follow); else keep the existing UDP path.
  - `ws_mode`, `ws_target`: store on `peer`. `ws_bearer`: store on `peer`; log ONLY the key name,
    never the value (mirror the `preshared_key` handler which logs no value).
- [ ] **Action 1.4.3** — modify `device/uapi.go` `handlePostConfig`: before `peer.Start()`, if
  `peer.wsEndpointURL != ""`, type-assert the bind to `conn.WebSocketBinder`; on failure return an
  error surfaced through `IpcSetOperation` (`websocket endpoint requires the websocket transport`);
  build via `ParseWSPeerEndpoint` and set `peer.endpoint.val`. NOTE: `handlePostConfig` currently
  returns nothing — change its signature to return `error` and propagate at ALL THREE call sites
  ([device/uapi.go:158](../../device/uapi.go#L158), [:170](../../device/uapi.go#L170),
  [:189](../../device/uapi.go#L189)). Record this in `## Deviations` (the plan code above did not
  foresee the signature change).
- [ ] **Action 1.4.4** — `IpcGetOperation` stays unchanged: it already emits `endpoint=<DstToString>`
  which round-trips the WS URL. `ws_mode`/`ws_target` are NOT echoed (not required; a running device
  already holds the built endpoint) and `ws_bearer` MUST NOT be echoed (D §4). Add a focused test
  (Task 1.5) asserting `ws_bearer` never appears in `IpcGet` output.

### [ ] Task 1.5 — US1 tests
- [ ] **Action 1.5.1** — create `conn/ws_endpoint_test.go`, `conn/ws_bind_test.go`,
  `conn/default_ws_test.go`, and augment `device/uapi_test.go` (or a new `device/uapi_ws_test.go`).

| Test | Verifies |
|---|---|
| `TestWSEndpoint_RoundTrip` | `ws`/`wss` URL + path + port survive `ParseEndpoint`→`DstToString`. |
| `TestWSEndpoint_DstKeys` | `DstIP`/`DstToBytes` stable and non-panicking for zero and set `dst`. |
| `TestWebSocketBind_ParseWSPeerEndpoint` | standard vs wstunnel; wstunnel without `ws_target` errors; bad scheme errors. |
| `TestNewBindForTransport` | `""`/`udp`→`*StdNetBind`; `ws`→`*WebSocketBind`; other→error. |
| `TestUAPI_WSKeys_Accepted` | `ws_listen`, ws-URL `endpoint`, `ws_mode`, `ws_target`, `ws_bearer` parse on a WS bind; a genuinely unknown key still errors. |
| `TestUAPI_WSListen_RequiresWSBind` | `ws_listen` on a UDP bind returns `IpcErrorInvalid`. |
| `TestUAPI_Bearer_NotEchoed` | after setting `ws_bearer`, `IpcGet` output contains neither the key nor the value. |
| `TestUAPI_Bearer_NotLogged` | a `set=1` with `ws_bearer=<token>` through a device built with a custom `&device.Logger{Verbosef, Errorf}` whose func fields append to a `bytes.Buffer` (`device.NewLogger` hardcodes `os.Stdout`, so it cannot capture): the token value never appears in the buffer. |
| `TestUAPI_WSKeys_NotLeakedAcrossPeers` | a two-peer `set=1` where only peer 1 sets `ws_mode`/`ws_target`/`ws_bearer`: peer 2's built endpoint is standard with no inherited target/bearer. |

- [ ] **DoD Task 1.5:** all US1 tests pass with `-race`.

**US1 DoD:** device builds and runs with `WG_TRANSPORT=ws` selecting the WS bind; WS config
round-trips over UAPI; `ws_bearer` never echoed; all GOOS compile; `go mod tidy` clean.

---

## [ ] US2 — Client bind: standard mode, single connection, ws:// then wss:// (P2)

**Why:** Make the WS client bind actually tunnel: dial, upgrade, one long-lived connection per peer
endpoint, read loop into the shared inbound queue, TLS for `wss`. Depends on: US1.

**Acceptance criteria:**
- [ ] Two wireguard-go instances complete a Noise handshake and exchange data over `ws://` and
      `wss://` on loopback, race-clean.
- [ ] Concurrent senders (send/keepalive/cookie) are serialized per connection (write mutex).
- [ ] A message larger than the caller buffer is dropped (guard, D8), not delivered truncated.
- [ ] `Close` unblocks every `ReceiveFunc` with `net.ErrClosed` (Bind contract,
      [conn/conn.go:41](../../conn/conn.go#L41)).

### [ ] Task 2.1 — Client connection + read loop
- [ ] **Action 2.1.1** — MODIFY `conn/ws_bind.go`: DELETE the three stub methods (`Open`/`Close`/`Send`)
  and REMOVE the now-unused `errors` and `net` imports (they were used ONLY by the stubs; the remaining
  code uses neither). All struct fields and both connection types are ALREADY declared in the US1
  struct, so nothing is added here. CREATE `conn/ws_client.go` holding the real
  `Open`/`makeWSReceiveFunc`/`Send` (methods on `WebSocketBind` may live in any file of package `conn`),
  the client read loop, and (with Action 2.1.2) the dial helper. The real `Close` is Action 2.1.3.

```go
// in conn/ws_client.go (wsClientConn/wsServerConn types are declared in ws_bind.go)
package conn

import (
	"context"
	"net"

	"github.com/coder/websocket"
)

// Concurrency contract (avoids send-on-closed-channel panics):
//   - b.inbound is NEVER closed. Shutdown is signalled by closing b.done.
//   - Every read loop registers on b.readWG; Close closes b.done, CloseNow's
//     the sockets to unblock reads, then b.readWG.Wait() joins all producers
//     BEFORE returning — no leak across Close/Open (BindUpdate) cycles.
// Client fields on WebSocketBind: conns map[string]*wsClientConn;
//   dialM sync.Mutex; ctx context.Context; ctxCancel context.CancelFunc;
//   readWG sync.WaitGroup. (inbound + done are already on the struct.)

func (b *WebSocketBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.inbound != nil {
		return nil, 0, ErrBindAlreadyOpen
	}
	b.closed = false
	inbound := make(chan wsInbound, 128)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	b.inbound, b.done, b.ctx, b.ctxCancel = inbound, done, ctx, cancel
	b.conns = make(map[string]*wsClientConn)
	b.dialBackoff = make(map[string]wsBackoff)
	// Server role returns b.openServer(ctx, port, inbound, done) here instead (ws_server.go).
	return []ReceiveFunc{makeWSReceiveFunc(inbound, done)}, port, nil
}

// makeWSReceiveFunc closes over the channels as LOCALS (captured under b.mu in Open),
// so the returned func never reads the b.done/b.inbound fields — no race with Close
// reassigning them across a BindUpdate (Close→Open) cycle.
func makeWSReceiveFunc(inbound <-chan wsInbound, done <-chan struct{}) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (int, error) {
		select {
		case <-done:
			return 0, net.ErrClosed
		case in := <-inbound:
			if len(in.data) > len(bufs[0]) { // oversize guard: drop, don't truncate
				return 0, nil
			}
			sizes[0] = copy(bufs[0], in.data)
			eps[0] = in.ep
			return 1, nil
		}
	}
}

func (b *WebSocketBind) Send(bufs [][]byte, ep Endpoint) error {
	we, ok := ep.(*WSEndpoint)
	if !ok {
		return ErrWrongEndpointType
	}
	// Server role dispatches by we.connID instead of dialing (ws_server.go).
	c, err := b.clientConn(we) // dial-on-demand + start read loop (idempotent)
	if err != nil {
		return err
	}
	c.writeM.Lock()
	defer c.writeM.Unlock()
	for _, buf := range bufs {
		if err := c.conn.Write(c.ctx, websocket.MessageBinary, buf); err != nil { // per-conn ctx (no b.ctx field race)
			return err
		}
	}
	return nil
}
```

  Read loop (`func (b *WebSocketBind) readLoop(c *wsClientConn, inbound chan<- wsInbound, done <-chan struct{})`,
  where `inbound`/`done` are captured from `b` under `b.mu` at dial time and passed in — NOT read from
  the fields in the loop, to stay race-free with `Open`/`Close`; started with `b.readWG.Add(1)` and
  `defer b.readWG.Done()`): `c.conn.SetReadLimit(wsReadLimit)`; loop `typ, data, err :=
  c.conn.Read(c.ctx)` (per-connection ctx, derived from `b.ctx` so a bind `Close` cancels it); on
  `err` → remove `c` from the registry, `c.conn.CloseNow()`, return (US4 turns
  this into a reconnect); on `typ==MessageBinary` → push via
  `select { case inbound <- wsInbound{data, c.ep}: case <-done: return; default: /* drop, lossy like UDP */ }`
  — the `<-done` case guarantees no send races with shutdown and, since `inbound` is never closed, no
  panic is possible. `websocket.MessageText` frames are ignored.

- [ ] **Action 2.1.2** — create `conn/ws_dial.go`: `clientConn` (get-or-dial, guarded by `dialM`) and
  the dial. Self-contained standard mode here; US3 modifies `dial` to route through `wsUpgradeRequest`,
  US5 modifies it to set `dialer.Control`.

```go
package conn

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// clientConn returns the live connection for we, dialing once on demand. The read
// loop is started here with the channel locals captured under b.mu (race-free).
func (b *WebSocketBind) clientConn(we *WSEndpoint) (*wsClientConn, error) {
	b.dialM.Lock()
	defer b.dialM.Unlock()

	b.mu.Lock()
	closed := b.closed
	existing := b.conns[we.url]
	inbound, done, ctx := b.inbound, b.done, b.ctx
	b.mu.Unlock()

	if closed {
		return nil, net.ErrClosed
	}
	if existing != nil {
		return existing, nil
	}

	c, err := b.dial(ctx, we)
	if err != nil {
		return nil, err
	}

	// Register + readWG.Add under b.mu WITH the closed re-check, so Add can never
	// run after Close set closed and began readWG.Wait() (WaitGroup misuse panic).
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		c.conn.CloseNow()
		return nil, net.ErrClosed
	}
	b.conns[we.url] = c
	b.readWG.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.readWG.Done()
		b.readLoop(c, inbound, done)
	}()
	return c, nil
}

func (b *WebSocketBind) dial(ctx context.Context, we *WSEndpoint) (*wsClientConn, error) {
	header := http.Header{}
	if we.bearer != "" {
		header.Set("Authorization", "Bearer "+we.bearer)
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second} // egress-pin/protect Control added by dialControl
	tr := &http.Transport{
		DialContext:     dialer.DialContext,
		TLSClientConfig: b.cfg.tlsClient, // nil ⇒ system roots
	}
	conn, _, err := websocket.Dial(ctx, we.url, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: tr},
		HTTPHeader: header,
	})
	if err != nil {
		return nil, fmt.Errorf("ws dial %s: %w", we.url, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	return &wsClientConn{conn: conn, ep: we, ctx: cctx, cancel: cancel}, nil
}
```

- [ ] **Action 2.1.3** — add the real `Close` in `conn/ws_client.go` (canonical for BOTH roles;
  replaces the deleted stub). `b.mu` MUST be released before `readWG.Wait()`: the read loops reacquire
  `b.mu` to deregister, so holding it across `Wait()` would deadlock. `b.inbound` is NEVER closed, so
  no producer can panic.

```go
func (b *WebSocketBind) Close() error {
	b.mu.Lock()
	if b.closed || b.done == nil {
		b.mu.Unlock()
		return nil // idempotent
	}
	b.closed = true
	done := b.done
	close(done) // unblocks every ReceiveFunc with net.ErrClosed
	if b.ctxCancel != nil {
		b.ctxCancel() // unblocks all read loops (they read with the per-conn ctx)
	}
	srv := b.srv
	// Detach the registries under the lock BEFORE ranging them: the read loops we
	// are about to unblock deregister via delete(b.conns/b.sconns, ...) under b.mu,
	// which on a nil field is a safe no-op — so no goroutine iterates or writes the
	// same map concurrently.
	clients := b.conns
	servers := b.sconns
	b.conns, b.sconns = nil, nil
	b.mu.Unlock()

	if srv != nil {
		_ = srv.Close() // stops the listener + Accept handlers (server role)
	}
	for _, c := range clients {
		c.conn.CloseNow() // idempotent; the read loop may also call it
	}
	for _, sc := range servers {
		sc.conn.CloseNow()
	}
	b.readWG.Wait() // join all read loops

	b.mu.Lock()
	b.inbound, b.done, b.srv = nil, nil, nil
	b.mu.Unlock()
	return nil
}
```

### [ ] Task 2.2 — Client TLS options
- [ ] **Action 2.2.1** — `buildWSOptionsFromEnv` (US1) already produces `cfg.tlsClient` from
  `WG_WS_TLS_CA`/`SERVERNAME`/`INSECURE`. Verify `wss://` uses it and `ws://` ignores it. No new file.

### [ ] Task 2.3 — US2 tests (shared client/loopback harness)
- [ ] **Action 2.3.1** — create `conn/ws_testhelpers_test.go` (package `conn_test`, external — it uses
  only exported API and imports `device`/`tun/tuntest`, which an internal test could not without an
  import cycle). This is the foundational shared harness reused by US2/US4/US6/US7; shown IN FULL.

```go
package conn_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// wsBridge is a test WS relay. In relay mode it pairs the first two accepted
// connections and forwards every binary message from each to the other, so two
// client-role WebSocketBinds dialing it tunnel end-to-end. In echo mode it reflects
// frames back (dial/upgrade unit checks). It tracks accepted connections so a test
// can force-drop them (reconnect tests).
type wsBridge struct {
	srv   *httptest.Server
	echo  bool
	mu    sync.Mutex
	peers []*websocket.Conn
}

func newWSBridge(t *testing.T, useTLS, echo bool) *wsBridge {
	t.Helper()
	b := &wsBridge{echo: echo}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		b.mu.Lock()
		b.peers = append(b.peers, c)
		b.mu.Unlock()
		b.serve(c)
	})
	if useTLS {
		b.srv = httptest.NewTLSServer(h)
	} else {
		b.srv = httptest.NewServer(h)
	}
	t.Cleanup(b.srv.Close)
	return b
}

func (b *wsBridge) serve(c *websocket.Conn) {
	ctx := context.Background()
	c.SetReadLimit(1 << 20) // allow oversize frames through so the CLIENT guard is what drops them
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			continue
		}
		if b.echo {
			_ = c.Write(ctx, websocket.MessageBinary, data)
			continue
		}
		b.mu.Lock()
		var other *websocket.Conn
		for _, p := range b.peers {
			if p != c {
				other = p
			}
		}
		b.mu.Unlock()
		if other != nil {
			_ = other.Write(ctx, websocket.MessageBinary, data)
		}
	}
}

// url converts the httptest http(s):// base into ws(s)://.
func (b *wsBridge) url() string { return "ws" + strings.TrimPrefix(b.srv.URL, "http") }

func (b *wsBridge) clientTLS() *tls.Config {
	if b.srv.TLS == nil {
		return nil
	}
	cp := x509.NewCertPool()
	cp.AddCert(b.srv.Certificate())
	return &tls.Config{RootCAs: cp}
}

func (b *wsBridge) dropAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.peers {
		_ = p.CloseNow()
	}
	b.peers = nil
}

// wgKeypair returns a clamped Curve25519 private key and its public key, hex-encoded.
func wgKeypair(t *testing.T) (priv, pub string) {
	t.Helper()
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	return hex.EncodeToString(sk[:]), hex.EncodeToString(pk)
}

// wsDevicePair brings up two WireGuard devices whose binds are client-role
// WebSocketBinds pointed at the same relay, so they tunnel over WS. Persistent
// keepalive makes both dial promptly so the relay can pair them. Returns the two
// in-memory TUNs for ping/pong assertions.
func newWSDevicePair(t *testing.T, useTLS bool) (a, b *tuntest.ChannelTUN) {
	t.Helper()
	br := newWSBridge(t, useTLS, false)
	priv1, pub1 := wgKeypair(t)
	priv2, pub2 := wgKeypair(t)
	mk := func(selfPriv, peerPub string) (*device.Device, *tuntest.ChannelTUN) {
		tdev := tuntest.NewChannelTUN()
		wsb, err := conn.NewWebSocketBind(
			conn.WithWSRole(conn.WSRoleClient),
			conn.WithWSClientTLS(br.clientTLS()),
		)
		if err != nil {
			t.Fatalf("bind: %v", err)
		}
		d := device.NewDevice(tdev.TUN(), wsb, device.NewLogger(device.LogLevelError, ""))
		cfg := fmt.Sprintf(
			"private_key=%s\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=1\nallowed_ip=0.0.0.0/0\n",
			selfPriv, peerPub, br.url(),
		)
		if err := d.IpcSet(cfg); err != nil {
			t.Fatalf("IpcSet: %v", err)
		}
		if err := d.Up(); err != nil {
			t.Fatalf("Up: %v", err)
		}
		t.Cleanup(d.Close)
		return d, tdev
	}
	_, a = mk(priv1, pub2)
	_, b = mk(priv2, pub1)
	// Give the handshake room to complete through the relay.
	time.Sleep(100 * time.Millisecond)
	return a, b
}
```

  NOTE: ALL US2/US4/US6/US7 behavioral tests live in `package conn_test` (external) and use only
  EXPORTED API — `NewWebSocketBind`, `Open` (which returns the `[]ReceiveFunc`), `Send`, `Close`,
  `ParseEndpoint` — plus `newWSBridge`/`newWSDevicePair`. None need `conn` internals, so there is no
  internal/external split or duplicated helper. The oversize/Close/concurrent tests drive a bind
  directly via `Open`→`Send`→calling the returned `ReceiveFunc`; the tunnel tests use
  `newWSDevicePair` and assert with `tuntest.Ping` + `ChannelTUN.Outbound`/`Inbound`, exactly as
  `device/device_test.go` does. The US5 pinning/path-monitor unit tests that DO need unexported access
  stay `package conn` (internal) and do not use this harness.

| Test | Verifies |
|---|---|
| `TestWSClient_Handshake_WS` | two devices tunnel over `ws://` via the relay; ping transits both directions. |
| `TestWSClient_Handshake_WSS` | same over `wss://` with the bridge's TLS cert pool. |
| `TestWSClient_ConcurrentSenders` | N goroutines `Send` on one endpoint; `-race` clean; frames not interleaved (write mutex). |
| `TestWSClient_OversizeDropped` | the bridge (echo) sends a frame > caller buffer; the `ReceiveFunc` returns `(0,nil)`; the tunnel survives. |
| `TestWSClient_CloseUnblocksReceive` | after `Close`, every `ReceiveFunc` returns `net.ErrClosed`. |

- [ ] **DoD Task 2.3:** all pass with `-race`; no goroutine leak after `Close` (before/after
  `runtime.NumGoroutine` settle with a short poll).

**US2 DoD:** two wireguard-go instances tunnel over `ws://` and `wss://` on loopback, race-clean.

---

## [ ] US3 — Client wstunnel dialect (interop) (P3)

**Why:** Speak the verified wstunnel wire contract (WORK_PLAN §2) so a wg-go client reaches a real
wstunnel server. Depends on: US2.

**Acceptance criteria:**
- [ ] The upgrade request is byte-shape-correct: `GET /<prefix>/events`, header
      `Sec-WebSocket-Protocol: v1, authorization.bearer.<jwt>`, JWT claims `{id,p:{"Udp":{"timeout":null}},r,rp}`.
- [ ] Destination (`r`,`rp`) comes from the peer `ws_target`; the peer `endpoint` URL is the wstunnel
      server itself.
- [ ] Masking is automatic (client role, `coder/websocket`) — no code; confirmed by the interop config.

### [ ] Task 3.1 — Dialect assembly
- [ ] **Action 3.1.1** — create `conn/ws_dialect.go`.

```go
package conn

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// wsUpgradeRequest builds the dial URL, HTTP header, and subprotocols for an
// endpoint's dialect. Standard: verbatim URL, optional Authorization: Bearer.
// Wstunnel: /<prefix>/events path + Sec-WebSocket-Protocol: v1, authorization.bearer.<jwt>.
func wsUpgradeRequest(e *WSEndpoint) (dialURL string, header http.Header, subprotocols []string, err error) {
	header = http.Header{}
	switch e.dialect {
	case wsDialectStandard:
		if e.bearer != "" {
			header.Set("Authorization", "Bearer "+e.bearer)
		}
		return e.url, header, nil, nil
	case wsDialectWstunnel:
		u, perr := url.Parse(e.url)
		if perr != nil {
			return "", nil, nil, fmt.Errorf("wstunnel endpoint %q: %w", e.url, perr)
		}
		prefix := strings.Trim(u.Path, "/")
		u.Path = "/" + prefix + "/events"
		token, jerr := wstunnelJWT(e.target, wsRandomSecret())
		if jerr != nil {
			return "", nil, nil, jerr
		}
		subprotocols = []string{"v1", "authorization.bearer." + token}
		if e.bearer != "" { // optional basic-auth: e.bearer is base64(user:pass)
			header.Set("Authorization", "Basic "+e.bearer)
		}
		return u.String(), header, subprotocols, nil
	default:
		return "", nil, nil, fmt.Errorf("unknown ws dialect %d", e.dialect)
	}
}
```

- [ ] **Action 3.1.2** — modify `go.mod`: add `github.com/golang-jwt/jwt/v5 v5.3.1` and
  `github.com/google/uuid v1.6.0`; `go mod tidy`; `govulncheck`. (`deps` scope — commit with US3.)
- [ ] **Action 3.1.3** — create `conn/ws_jwt.go`.

```go
package conn

import (
	"crypto/rand"
	"fmt"
	"net"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// wstunnelClaims embeds jwt.RegisteredClaims to satisfy the jwt.Claims interface;
// the wstunnel-specific fields are non-registered. timeout is *int so it marshals
// to JSON null for the UDP protocol variant.
type wstunnelClaims struct {
	ID string        `json:"id"`
	P  wstunnelProto `json:"p"`
	R  string        `json:"r"`
	RP int           `json:"rp"`
	jwt.RegisteredClaims
}

type wstunnelProto struct {
	Udp struct {
		Timeout *int `json:"timeout"`
	} `json:"Udp"`
}

func wsRandomSecret() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand; error ignored is acceptable here (never returns err on unix/windows)
	return b
}

// wstunnelJWT builds the HS256 token. The wstunnel server does NOT verify the
// signature, but the token must be a well-formed HS256 JWT — golang-jwt guarantees that.
func wstunnelJWT(target string, secret []byte) (string, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("ws_target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("ws_target port %q: %w", portStr, err)
	}
	claims := wstunnelClaims{ID: uuid.NewString(), R: host, RP: port}
	// claims.P.Udp.Timeout stays nil ⇒ JSON null (UDP).
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}
```

- [ ] **Action 3.1.4** — modify `conn/ws_dial.go` `dial`: replace the inline standard-mode header with
  `url, header, subprotos, err := wsUpgradeRequest(we)`, dial `url`, and pass
  `Subprotocols: subprotos` in `DialOptions`.

### [ ] Task 3.2 — US3 tests + Manual QA
- [ ] **Action 3.2.1** — create `conn/ws_dialect_test.go`, `conn/ws_jwt_test.go`.

| Test | Verifies |
|---|---|
| `TestWSUpgrade_Standard` | verbatim path; `Authorization: Bearer` present iff bearer set; no subprotocol. |
| `TestWSUpgrade_Wstunnel_Path` | path is `/<prefix>/events` derived from the endpoint URL. |
| `TestWSUpgrade_Wstunnel_Subprotocol` | `Sec-WebSocket-Protocol: v1, authorization.bearer.<jwt>`. |
| `TestWstunnelJWT_Claims` | decoded header+payload: `alg=HS256`; `id` is a valid `uuid.Parse` v4; `p.Udp.timeout==null`; `r`/`rp` from `ws_target`. |
| `TestWstunnelJWT_Verifiable` | `jwt.Parse` with the same secret validates the token (round-trip sanity). |

- [ ] **Action 3.2.2** — add a **Manual QA** note to the plan's `## Manual QA` section (below): connect
  through the user's live wstunnel server using the user's existing `~/Downloads` config (private key
  present — the implementer MUST NOT open/print it), tunnel real traffic both ways; the pre/post
  wstunnel wrapper scripts in that config are no longer needed once the transport is integrated. This
  also settles the masking question empirically (WORK_PLAN §7).

- [ ] **DoD Task 3.2:** unit tests pass with `-race`; Manual QA documented (not automated).

**US3 DoD:** generated handshake is byte-shape-correct; Manual QA reaches `101` and tunnels.

---

## [ ] US4 — Client resilience: reconnect (BindUpdate-first) + ping backstop (P4)

**Why:** Survive network switches and silent drops per D10/D12: OS-notification-driven `BindUpdate`
is primary, socket errors secondary, WS ping the backstop. Depends on: US2.

**Acceptance criteria:**
- [ ] A `Close`→`Open` cycle (what `BindUpdate` performs) tears down all connections and re-arms; the
      tunnel resumes on the next `Send` with a fresh dial (DNS re-resolved).
- [ ] A server-side drop makes the client re-dial with bounded backoff and resume, no restart.
- [ ] The ping ticker detects a half-open connection and forces a re-dial.
- [ ] No goroutine leak across many reconnects (`-race` + leak check).

### [ ] Task 4.1 — Reconnect + ping
- [ ] **Action 4.1.1** — (a) modify `conn/ws_client.go`: the read loop, on error, removes the dead
  conn from `b.conns` (under `b.mu`) so the next `Send` re-dials with a fresh `websocket.Dial`
  (re-resolving DNS); surface `net.ErrClosed` only when `b.closed`. (b) modify `conn/ws_dial.go`: add
  bounded per-endpoint dial backoff in `clientConn`, using the `dialBackoff map[string]wsBackoff` field
  (declared in the US1 struct, initialised in `Open`) — serialised by `dialM`, which `clientConn`
  already holds, so no extra lock. (`ws_dial.go` already imports `time` and `fmt`.)

```go
// clientConn (ws_dial.go), modified: dialBackoff is read/written under b.mu (same
// discipline as b.conns) — NOT under dialM — so it can never race with Open's
// reassignment on a BindUpdate. dialM still serialises the whole dial path.
// First b.mu snapshot additionally reads the backoff entry:
b.mu.Lock()
closed := b.closed
existing := b.conns[we.url]
inbound, done, ctx := b.inbound, b.done, b.ctx
bo, backing := b.dialBackoff[we.url]
b.mu.Unlock()
if closed {
	return nil, net.ErrClosed
}
if existing != nil {
	return existing, nil
}
if backing && bo.until.After(time.Now()) {
	return nil, fmt.Errorf("ws dial backoff for %s", we.url) // cooling down; device retries later
}

c, err := b.dial(ctx, we)

b.mu.Lock()
if err != nil {
	nb := b.dialBackoff[we.url]
	nb.d = min(max(nb.d*2, b.cfg.backoffMin), b.cfg.backoffMax)
	if nb.d == 0 {
		nb.d = b.cfg.backoffMin
	}
	nb.until = time.Now().Add(nb.d)
	b.dialBackoff[we.url] = nb
	b.mu.Unlock()
	return nil, err
}
if b.closed {
	b.mu.Unlock()
	c.conn.CloseNow()
	return nil, net.ErrClosed
}
delete(b.dialBackoff, we.url) // success resets backoff
b.conns[we.url] = c
b.readWG.Add(1)
b.mu.Unlock()
```

  (`min`/`max` are Go 1.21+ builtins; the module targets go 1.26. This supersedes the register tail of
  the base `clientConn` from Action 2.1.2.) Action 4.1.2 raises the `Add(1)` above to `Add(2)` and
  starts `pingLoop` as the second tracked goroutine.
- [ ] **Action 4.1.2** — create `conn/ws_ping.go`, and modify `clientConn` (in `conn/ws_dial.go`) to
  launch `pingLoop` alongside `readLoop` under the same `readWG` (change its `readWG.Add(1)` to
  `Add(2)` and start both goroutines, each `defer b.readWG.Done()`), so `Close` joins the ping
  goroutines too (no leak). US8 modifies `pingLoop` to record RTT via `b.metrics.observeRTT` — kept out
  of here to avoid depending on the metrics field.

```go
package conn

import "time"

// pingLoop pings the connection every cfg.pingInterval; on failure it cancels the
// connection, which unblocks its read loop and makes the next Send re-dial. It exits
// when the per-connection ctx is cancelled (drop or bind Close).
func (b *WebSocketBind) pingLoop(c *wsClientConn) {
	if b.cfg.pingInterval <= 0 {
		return
	}
	t := time.NewTicker(b.cfg.pingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			if err := c.conn.Ping(c.ctx); err != nil {
				c.cancel() // triggers read-loop exit + reconnect
				return
			}
		}
	}
}
```
- [ ] **Action 4.1.3** — confirm `BindUpdate` semantics: `device.BindUpdate` already calls
  `bind.Close()` then `bind.Open()` ([device/device.go:471-490](../../device/device.go#L471)). Ensure
  `WebSocketBind.Close`/`Open` are a clean teardown/re-arm (idempotent; no leaked goroutines; a new
  `inbound` channel + fresh registry on re-Open). No device-core change.

### [ ] Task 4.2 — US4 tests
- [ ] **Action 4.2.1** — extend `conn/ws_client_test.go`.

| Test | Verifies |
|---|---|
| `TestWSClient_BindUpdateCycle` | `Close` then `Open` re-arms; a subsequent handshake succeeds; old goroutines gone. |
| `TestWSClient_ServerDropReconnect` | `wsEchoServer.dropAll()` → client re-dials and data resumes. |
| `TestWSClient_PingTimeoutReconnect` | a server that stops ponging triggers a re-dial via the ping backstop. |
| `TestWSClient_BackoffBounded` | repeated dial failures back off within `[backoffMin, backoffMax]`; no busy loop. |
| `TestWSClient_NoGoroutineLeak` | after M reconnect cycles, goroutine count returns to baseline. |

- [ ] **DoD Task 4.2:** all pass with `-race`.

**US4 DoD:** tunnel survives forced disconnects / DNS changes / `BindUpdate` cycles without a device
restart.

---

## [ ] US5 — Client egress pinning, SetMark, standalone path monitors (P5, D11, D19)

**Why:** Stop the WS dial from looping back into the tun (D11) and drive `BindUpdate` from OS network
changes on the standalone daemon (D19). Depends on: US4.

**Acceptance criteria:**
- [ ] Every (re)dial binds to the physical egress interface: `IP_BOUND_IF`/`IPV6_BOUND_IF` (Darwin),
      `SO_MARK` (Linux/Android), recomputed each dial, via `net.Dialer.Control`.
- [ ] `WebSocketBind.SetMark` applies the mark to subsequent dials.
- [ ] Standalone daemon reconnects on a real network change: Linux netlink watcher and macOS cgo
      `NWPathMonitor` bridge call `device.BindUpdate()`; other GOOS use a no-op monitor.
- [ ] The mobile protect callback (`func(fd int)`) runs inside `Dialer.Control` for every dial (also
      exercised here; consumed by US9).

### [ ] Task 5.1 — Egress pinning (build-tagged)
- [ ] **Action 5.1.1** — create `conn/ws_pinning_darwin.go` (`//go:build darwin`). `IP_BOUND_IF`
  (`0x19`) / `IPV6_BOUND_IF` (`0x7d`) verified in x/sys@v0.32.0.

```go
//go:build darwin

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func (b *WebSocketBind) dialControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		idx := b.egressIfIndex() // recomputed per dial; 0 ⇒ skip pin
		v6 := wsIsIPv6(address)
		var serr error
		cerr := c.Control(func(fd uintptr) {
			if idx > 0 {
				if v6 {
					serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx)
				} else {
					serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
				}
			}
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

- [ ] **Action 5.1.2** — create `conn/ws_pinning_linux.go` (`//go:build linux`; also compiled for
  `GOOS=android`, which satisfies `linux`). `SO_MARK` verified in x/sys@v0.32.0.

```go
//go:build linux

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func (b *WebSocketBind) dialControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		mark := b.mark.Load()
		cerr := c.Control(func(fd uintptr) {
			if mark != 0 {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			}
			if serr == nil && b.cfg.protect != nil { // Android: VpnService.protect via the callback
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

- [ ] **Action 5.1.3** — create `conn/ws_pinning_default.go` (`//go:build !darwin && !linux`):
  protect-only (no pinning syscall on these platforms; matches the no-fwmark platforms today).

```go
//go:build !darwin && !linux

package conn

import "syscall"

func (b *WebSocketBind) dialControl() func(network, address string, c syscall.RawConn) error {
	if b.cfg.protect == nil {
		return nil // nil Control is valid
	}
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) { b.cfg.protect(int(fd)) })
	}
}
```

- [ ] **Action 5.1.4** — create `conn/ws_iface_darwin.go` ONLY. All three helpers
  (`egressIfIndex`, `wsIsIPv6`, `defaultEgressIfIndex`) and the package-level test seam
  `egressIfIndexFn` live here, `darwin`-tagged, because the ONLY caller is the darwin `dialControl`
  (Action 5.1.1). Putting them in an untagged file would make them unused on the Linux/other builds
  (staticcheck `U1000` fails the zero-lint gate on `ubuntu-latest`). No shared `ws_iface.go` and no
  non-darwin `defaultEgressIfIndex` are created (nothing off-darwin calls them). Do NOT add an
  `egressIfIndexFn` struct field — a struct field unused on non-darwin builds would also trip `U1000`.

```go
//go:build darwin

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
```
- [ ] **Action 5.1.5** — modify `conn/ws_dial.go` `dial`: set `dialer.Control = b.dialControl()`
  (recomputes egress + protect on every dial).

### [ ] Task 5.2 — Standalone path monitors (build-tagged, process-level)
- [ ] **Action 5.2.1** — create `conn/ws_pathmonitor.go`: interface + constructor selection.

```go
package conn

import (
	"sync"
	"time"
)

// WSPathMonitor watches for OS network-path changes and invokes onChange (which
// the daemon wires to device.BindUpdate). Standalone daemon only; embedded apps
// drive BindUpdate themselves.
type WSPathMonitor interface {
	Start(onChange func()) error
	Close() error
}

func NewWSPathMonitor(l Logger) WSPathMonitor { return newWSPathMonitor(l) } // per-OS

// wsDebounce coalesces a burst of change events into a single onChange after a
// quiet period. Shared by the platform monitors; also the unit-testable core.
type wsDebounce struct {
	d  time.Duration
	fn func()
	mu sync.Mutex
	t  *time.Timer
}

func newWSDebounce(d time.Duration, fn func()) *wsDebounce { return &wsDebounce{d: d, fn: fn} }

func (w *wsDebounce) trigger() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.t == nil {
		w.t = time.AfterFunc(w.d, w.fn)
	} else {
		w.t.Reset(w.d)
	}
}

func (w *wsDebounce) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.t != nil {
		w.t.Stop()
	}
}
```

- [ ] **Action 5.2.2** — create `conn/ws_pathmonitor_linux.go` (`//go:build linux && !android`). The
  `!android` term is REQUIRED: `GOOS=android` satisfies `linux` (this repo relies on that in
  `conn/mark_unix.go`), so a bare `linux` file WOULD wrongly compile on android where API 30+ forbids
  in-process `NETLINK_ROUTE` `bind()` (D19). NOT the existing `startRouteListener` (no-ops for
  non-`*StdNetBind`, [device/sticky_linux.go:31-33](../../device/sticky_linux.go#L31)). Constants
  verified in x/sys@v0.32.0; `rwcancel` API per `rwcancel/rwcancel.go`.

```go
//go:build linux && !android

package conn

import (
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/rwcancel"
)

type netlinkMonitor struct {
	log    Logger
	sock   int
	cancel *rwcancel.RWCancel
}

func newWSPathMonitor(l Logger) WSPathMonitor { return &netlinkMonitor{log: l} }

func (m *netlinkMonitor) Start(onChange func()) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	if err := unix.Bind(sock, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR |
			unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE | unix.RTMGRP_LINK,
	}); err != nil {
		unix.Close(sock)
		return err
	}
	cancel, err := rwcancel.NewRWCancel(sock) // sets non-block
	if err != nil {
		unix.Close(sock)
		return err
	}
	m.sock, m.cancel = sock, cancel
	go m.loop(onChange)
	return nil
}

func (m *netlinkMonitor) loop(onChange func()) {
	defer m.cancel.Close()
	defer unix.Close(m.sock)
	debounce := newWSDebounce(300*time.Millisecond, onChange)
	defer debounce.stop()
	buf := make([]byte, 1<<16)
	for {
		var n int
		var err error
		for {
			n, _, _, _, err = unix.Recvmsg(m.sock, buf, nil, 0)
			if err == nil || !rwcancel.RetryAfterError(err) {
				break
			}
			if !m.cancel.ReadyRead() {
				return // cancelled by Close
			}
		}
		if err != nil {
			return
		}
		if n >= unix.SizeofNlMsghdr {
			debounce.trigger()
		}
	}
}

func (m *netlinkMonitor) Close() error {
	if m.cancel != nil {
		m.cancel.Cancel()
	}
	return nil
}
```

- [ ] **Action 5.2.3** — create `conn/ws_pathmonitor_darwin.go` (`//go:build darwin && cgo`). C
  signatures verified against the SDK `Network.framework/.../path_monitor.h` (all
  `API_AVAILABLE(macos(10.14))`). Also compiled for `GOOS=ios` (implies `darwin`) — harmless (an
  embedded app never starts it).

```go
//go:build darwin && cgo

package conn

/*
#cgo LDFLAGS: -framework Network -framework CoreFoundation
#include <Network/Network.h>
#include <dispatch/dispatch.h>

extern void wsPathChangedGo(uintptr_t handle);

static nw_path_monitor_t wsStartPathMonitor(uintptr_t handle) {
	nw_path_monitor_t m = nw_path_monitor_create();
	dispatch_queue_t q = dispatch_queue_create("wireguard.ws.pathmonitor", DISPATCH_QUEUE_SERIAL);
	nw_path_monitor_set_queue(m, q);
	nw_path_monitor_set_update_handler(m, ^(nw_path_t path) {
		if (nw_path_get_status(path) == nw_path_status_satisfied) {
			wsPathChangedGo(handle);
		}
	});
	nw_path_monitor_start(m);
	return m;
}
static void wsStopPathMonitor(nw_path_monitor_t m) { nw_path_monitor_cancel(m); }
*/
import "C"

import (
	"runtime/cgo"
	"sync"
	"time"
)

type nwMonitor struct {
	log      Logger
	mu       sync.Mutex
	mon      C.nw_path_monitor_t
	handle   cgo.Handle
	started  bool
	debounce *wsDebounce
}

func newWSPathMonitor(l Logger) WSPathMonitor { return &nwMonitor{log: l} }

func (m *nwMonitor) Start(onChange func()) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil
	}
	m.debounce = newWSDebounce(300*time.Millisecond, onChange)
	m.handle = cgo.NewHandle(m)
	m.mon = C.wsStartPathMonitor(C.uintptr_t(m.handle))
	m.started = true
	return nil
}

func (m *nwMonitor) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		return nil
	}
	C.wsStopPathMonitor(m.mon)
	m.handle.Delete()
	if m.debounce != nil {
		m.debounce.stop()
	}
	m.started = false
	return nil
}

//export wsPathChangedGo
func wsPathChangedGo(handle C.uintptr_t) {
	if m, ok := cgo.Handle(handle).Value().(*nwMonitor); ok && m.debounce != nil {
		m.debounce.trigger()
	}
}
```

- [ ] **Action 5.2.4** — create the no-op monitor covering EVERY remaining build combination so all
  targets compile with exactly one `newWSPathMonitor`: `conn/ws_pathmonitor_darwin_nocgo.go`
  (`//go:build darwin && !cgo`) and `conn/ws_pathmonitor_default.go`
  (`//go:build (!linux && !darwin) || android`). The `|| android` term is REQUIRED so android (which
  satisfies `linux`) gets the no-op and does NOT also match the netlink file (`linux && !android`);
  together the tags partition all targets with no overlap and no gap.

```go
//go:build (!linux && !darwin) || android

package conn

type noopMonitor struct{}

func newWSPathMonitor(l Logger) WSPathMonitor { return noopMonitor{} }
func (noopMonitor) Start(onChange func()) error { return nil }
func (noopMonitor) Close() error                { return nil }
```

  (`ws_pathmonitor_darwin_nocgo.go` is identical but tagged `//go:build darwin && !cgo`.)
- [ ] **Action 5.2.5** — modify `main.go`: in the foreground path, after
  `device := device.NewDevice(tdev, bind, logger)` ([main.go:225](../../main.go#L225)) and only when
  `transport=="ws"`, construct
  `mon := conn.NewWSPathMonitor(conn.Logger{Verbosef: logger.Verbosef, Errorf: logger.Errorf})` and
  `mon.Start(func(){ _ = device.BindUpdate() })`; `mon.Close()` in the cleanup path alongside
  `uapi.Close()`/`device.Close()`. (`main.go` has NO `device.Up()` call — the interface is brought up
  via the TUN up event; the monitor is started right after device construction in the post-daemonize
  foreground process. Standalone only; not in `main_windows.go` — Windows is a debug harness with no
  such monitor.)

### [ ] Task 5.3 — SetMark + US5 tests
- [ ] **Action 5.3.1** — `WebSocketBind.SetMark` (US1 skeleton) already stores the mark; confirm the
  Linux control hook reads `cfg.mark` at dial time.
- [ ] **Action 5.3.2** — create `conn/ws_pinning_test.go`, `conn/ws_pathmonitor_test.go`.

| Test | Verifies |
|---|---|
| `TestWSPinning_ControlSelection` | per-GOOS the right control hook is selected (build-tag-gated compile + behavior with an injected fd). |
| `TestWSPinning_ProtectInvoked` | `cfg.protect` is called once per dial with the socket fd (fake control). |
| `TestWSPinning_RecomputesOnRedial` | interface detection runs on each dial (injected detector counts calls). |
| `TestWSPathMonitor_Noop` | default/no-cgo monitor `Start` returns nil and never fires. |
| `TestWSPathMonitor_Plumbing` | injected event → `onChange` invoked exactly once after debounce (linux/darwin behavior tested via the injectable core). |
| `TestWebSocketBind_SetMark` | mark stored; Linux control applies it (fake `SetsockoptInt`). |

- [ ] **DoD Task 5.3:** pass with `-race`; real pinning + real path events are Manual QA (on-device).

**US5 DoD:** on a host whose default route is the tun, the WS transport still egresses via the
physical link and re-pins after a switch; standalone daemon reconnects on a network change.

---

## [ ] US6 — Server bind: standard mode, multi-peer, roaming, bearer (P6)

**Why:** Serve many WS clients from one wireguard-go server, with reconnect-roaming and the optional
bearer gate. Depends on: US1.

**Acceptance criteria:**
- [ ] One wireguard-go server accepts multiple concurrent WS clients over `ws://`/`wss://`.
- [ ] Missing/invalid bearer → HTTP `401` before upgrade (D6); WireGuard Noise remains the real auth.
- [ ] A client reconnecting on a new TCP connection rebinds via `SetEndpointFromPacket`; traffic
      resumes to the new connection.
- [ ] `DstIP`/`DstToBytes` derive from each connection's remote address → per-client rate-limiter +
      MAC2 identity.

### [ ] Task 6.1 — Server listener + per-connection transport
- [ ] **Action 6.1.1** — create `conn/ws_server.go` (the `srv`/`sconns`/`nextConnID` fields and
  `wsServerConn` type are already declared in `ws_bind.go`). `openServer` is invoked from the
  US6-modified `Open` with the channel locals AND the open `ctx` captured under `b.mu`.

```go
package conn

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/coder/websocket"
)

// wsPeerAddr parses the direct peer address. The trusted-proxy XFF resolver
// (conn/ws_xff.go) replaces this call when trusted proxies are configured.
func wsPeerAddr(r *http.Request) netip.AddrPort {
	ap, _ := netip.ParseAddrPort(r.RemoteAddr)
	return ap
}

func (b *WebSocketBind) openServer(ctx context.Context, port uint16, inbound chan wsInbound, done <-chan struct{}) ([]ReceiveFunc, uint16, error) {
	u, err := url.Parse(b.cfg.listenURL)
	if err != nil {
		return nil, 0, err
	}
	b.sconns = make(map[uint64]*wsServerConn)
	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		if !b.checkBearer(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		dst := wsPeerAddr(r)
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			c.CloseNow()
			return
		}
		b.nextConnID++
		id := b.nextConnID
		sc := &wsServerConn{conn: c, id: id, ctx: ctx}
		b.sconns[id] = sc
		b.readWG.Add(1) // under b.mu with the closed check (no WaitGroup misuse)
		b.mu.Unlock()
		defer b.readWG.Done()
		b.serverReadLoop(sc, &WSEndpoint{dst: dst, connID: id}, inbound, done)
	})
	b.srv = &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", u.Host)
	if err != nil {
		return nil, 0, err
	}
	go func() {
		if b.cfg.tlsServer != nil {
			b.srv.TLSConfig = b.cfg.tlsServer
			_ = b.srv.ServeTLS(ln, "", "") // certs come from tlsServer
		} else {
			_ = b.srv.Serve(ln)
		}
	}()
	return []ReceiveFunc{makeWSReceiveFunc(inbound, done)}, port, nil
}

func (b *WebSocketBind) checkBearer(r *http.Request) bool {
	if b.cfg.serverBearer == "" {
		return true // gate off (no bearer configured)
	}
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(p) || h[:len(p)] != p {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h[len(p):]), []byte(b.cfg.serverBearer)) == 1
}

func (b *WebSocketBind) serverReadLoop(sc *wsServerConn, ep *WSEndpoint, inbound chan<- wsInbound, done <-chan struct{}) {
	sc.conn.SetReadLimit(wsReadLimit)
	defer func() {
		b.mu.Lock()
		delete(b.sconns, sc.id)
		b.mu.Unlock()
		sc.conn.CloseNow()
	}()
	for {
		typ, data, err := sc.conn.Read(sc.ctx) // per-conn ctx captured at accept (no b.ctx field race)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			continue
		}
		select {
		case inbound <- wsInbound{data: data, ep: ep}:
		case <-done:
			return
		default: // lossy like UDP
		}
	}
}
```

  `wsPeerAddr` is the US6 client-address source; US7 (Task 7.1) swaps that call for
  `resolveClientAddr(r, b.cfg.trustedProxies)`.
- [ ] **Action 6.1.2** — modify `Send` in `conn/ws_client.go` to branch on `b.cfg.role`: the client
  path is unchanged (dial-on-demand, writes with `c.ctx`); the server path looks up the connection by
  `we.connID` under `b.mu` and, if absent (client gone), returns an error (the peer re-handshakes on
  reconnect), writing under `sc.writeM` with `sc.ctx`. Also modify `Open` to add, before the client
  setup: `if b.cfg.role == WSRoleServer { return b.openServer(ctx, port, inbound, done) }` (using the
  locals captured in `Open`).
- [ ] **Action 6.1.3** — roaming: no device-core change — the device already calls
  `SetEndpointFromPacket(elem.endpoint)` on handshake init/response
  ([device/receive.go:374,401](../../device/receive.go#L374)). Because each accepted connection
  produces a `WSEndpoint` with its own `connID`, a reconnecting client's handshake naturally rebinds
  the peer to the new connection. Server `WSEndpoint` MUST carry a stable `dst` so MAC2/limiter
  identity is per-client across reconnects.
- [ ] **Action 6.1.4** — server shutdown is handled by the canonical `Close` (Action 2.1.3): it
  `http.Server.Close()`s the listener and `CloseNow`s all server conns before `b.readWG.Wait()`. No
  separate server Close path; `b.inbound` is never closed.

### [ ] Task 6.2 — US6 tests
- [ ] **Action 6.2.1** — create `conn/ws_server_test.go` (reuses the US2 harness; a real
  `WebSocketBind` server + N client binds).

| Test | Verifies |
|---|---|
| `TestWSServer_MultiClient` | 3 clients each complete a handshake and exchange data concurrently, race-clean. |
| `TestWSServer_BearerReject` | with `WithWSServerBearer(tok)`: no/wrong `Authorization: Bearer` → `401`, no upgrade; matching token → tunnel; empty config ⇒ gate off (any/no bearer upgrades). |
| `TestWSServer_Roaming` | a client re-dials on a new connection; server rebinds peer and data resumes. |
| `TestWSServer_PerClientDstIdentity` | two clients yield distinct `DstIP`/`DstToBytes` (limiter/cookie isolation). |
| `TestWSServer_CloseShutsDown` | `Close` stops the listener and unblocks receivers with `net.ErrClosed`. |
| `TestWSServer_BearerNotLogged` | a server built with `WithWSServerBearer(tok)` and a captured logger: a rejected AND an accepted upgrade both leave the token value absent from log output. |

- [ ] **DoD Task 6.2:** pass with `-race`.

**US6 DoD:** one wireguard-go server serves multiple WS clients, race-clean, with roaming.

---

## [ ] US7 — Server trusted-proxy X-Forwarded-For (P7, D13)

**Why:** Behind a native HTTP reverse proxy (Traefik/Caddy), keep the rate-limiter + MAC2 cookies
per-client by trusting `XFF` ONLY from configured proxy CIDRs. Depends on: US6. (NOT the wstunnel
path — resolved in WORK_PLAN §7.)

**Acceptance criteria:**
- [ ] When `r.RemoteAddr` ∈ a configured trusted-proxy CIDR, the endpoint IP comes from the first
      `XFF` hop; otherwise `XFF` is ignored entirely.
- [ ] Forged `XFF` from an untrusted source has no effect.
- [ ] Per-client rate-limiting/cookies are restored behind a trusted proxy.

### [ ] Task 7.1 — XFF resolution
- [ ] **Action 7.1.1** — create `conn/ws_xff.go`.

```go
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
```

- [ ] **Action 7.1.2** — modify `conn/ws_server.go`: replace the `dst := wsPeerAddr(r)` call in the
  accept handler with `dst := resolveClientAddr(r, b.cfg.trustedProxies)`, delete the now-unused
  `wsPeerAddr` helper, and REMOVE the now-orphaned `net/netip` import (it was `wsPeerAddr`'s only user;
  `net` stays, used by `net.Listen`).

### [ ] Task 7.2 — US7 tests
- [ ] **Action 7.2.1** — create `conn/ws_xff_test.go`.

| Test | Verifies |
|---|---|
| `TestXFF_TrustedHonored` | peer ∈ trusted CIDR → `dst` from `XFF` first hop. |
| `TestXFF_UntrustedIgnored` | peer ∉ trusted → raw peer addr; forged `XFF` ignored. |
| `TestXFF_MultiHopStripsTrusted` | chained trusted proxies → first untrusted hop chosen. |
| `TestXFF_EmptyConfig` | no trusted CIDRs → always raw peer addr. |

- [ ] **DoD Task 7.2:** pass with `-race`.

**US7 DoD:** behind a configured proxy, handshake rate-limiting/cookies are per-client, not collapsed.

---

## [ ] US8 — Prometheus metrics (P8, D15)

**Why:** Expose high-level + per-peer metrics over an optional, off-by-default HTTP listener, from a
scrape-time collector over existing peer atomics + WS-bind counters + device-core handshake counters.
Depends on: US1 (collector/listener/device counters); consumes surfaces from US2/US4/US6.

**Acceptance criteria:**
- [ ] Metrics scrape at both levels; default build exposes nothing until `WG_METRICS_LISTEN` is set.
- [ ] The collector reads device peer stats through a consumer-defined interface (no device internals
      leaked); label cardinality is bounded.
- [ ] `prometheus/client_golang` v1.24.1 added; `go mod tidy` clean; `govulncheck` clean.

### [ ] Task 8.1 — Device-core read surfaces + counters
- [ ] **Action 8.1.1** — create `device/stats.go`: a read-only peer-iteration accessor exposing the
  EXISTING atomics ([device/peer.go:24-26](../../device/peer.go#L24)) without leaking internals.

```go
package device

import "time"

type PeerStats struct {
	PublicKey         [32]byte
	Endpoint          string // DstToString of the peer's current endpoint ("" if none) — join key for WS per-endpoint stats
	TxBytes, RxBytes  uint64
	LastHandshakeNano int64
	Connected         bool // lastHandshake recent (derived)
}

// IterPeerStats calls fn for each peer under RLock, snapshotting the existing
// peer atomics plus the endpoint string (peer.endpoint locked briefly).
func (device *Device) IterPeerStats(fn func(PeerStats)) {
	device.peers.RLock()
	defer device.peers.RUnlock()
	now := time.Now()
	for pk, peer := range device.peers.keyMap {
		peer.endpoint.Lock()
		ep := ""
		if peer.endpoint.val != nil {
			ep = peer.endpoint.val.DstToString()
		}
		peer.endpoint.Unlock()
		last := peer.lastHandshakeNano.Load()
		fn(PeerStats{
			PublicKey:         [32]byte(pk),
			Endpoint:          ep,
			TxBytes:           peer.txBytes.Load(),
			RxBytes:           peer.rxBytes.Load(),
			LastHandshakeNano: last,
			Connected:         last != 0 && now.Sub(time.Unix(0, last)) < 3*KeepaliveTimeout,
		})
	}
}

// HandshakeStats loads the handshake counters.
func (device *Device) HandshakeStats() (rateLimited, completed, failed uint64) {
	return device.handshakeRateLimited.Load(), device.handshakesCompleted.Load(), device.handshakesFailed.Load()
}
```

  NOTE: `device` does NOT import `metrics` and implements NO metrics interface. The daemon (Action
  8.3.4) reads these methods and maps them into the `metrics` package's own DTOs — no cross-package
  structural-typing dependency in either direction (go.md: interfaces at the consumer, no import cycle).

- [ ] **Action 8.1.2** — modify `device/device.go` (Device struct): add
  `handshakesCompleted, handshakesFailed, handshakeRateLimited atomic.Uint64`.
- [ ] **Action 8.1.3** — instrument the handshake paths (counters only — no behavior/wire change):
  - `handshakesCompleted`: increment inside `BeginSymmetricSession`
    ([device/noise-protocol.go:612](../../device/noise-protocol.go#L612)) on success, since it is
    called by BOTH the initiator (`device/receive.go:413`) AND the responder
    (`device/send.go:159`, from `SendHandshakeResponse`) — so a WS SERVER (the responder, this fork's
    central role) counts its completed handshakes too. (`device/noise-protocol.go`.)
  - `handshakeRateLimited`: increment at the limiter rejection
    ([device/receive.go:336](../../device/receive.go#L336)).
  - `handshakesFailed`: increment on decode/consume failures on the handshake path in
    `device/receive.go` (invalid initiation/response, `ConsumeMessageInitiation`/`...Response` nil).

### [ ] Task 8.2 — WS-bind counters
- [ ] **Action 8.2.1** — create `conn/ws_metrics.go` and add a `metrics wsMetricsState` field to
  `WebSocketBind`. The per-endpoint map (keyed by `DstToString`, the same string surfaced as
  `device.PeerStats.Endpoint`) is what gives the per-peer reconnect/ping-rtt metrics a real source
  (P8/D15).

```go
package conn

import "sync"

type wsEndpointMetric struct {
	reconnects     uint64
	pingRTTSeconds float64
}

type wsMetricsState struct {
	mu                  sync.Mutex
	connectionsActive   uint64
	connectionsByResult map[string]uint64 // e.g. "ok","dial_error"
	reconnectsTotal     uint64
	rxMessages, txMessages, rxBytes, txBytes uint64
	droppedByReason     map[string]uint64 // e.g. "oversize","queue_full"
	lastPingRTTSeconds  float64            // most recent RTT across all conns (high-level metric)
	perEndpoint         map[string]*wsEndpointMetric
}

// WSMetrics is a scrape-time snapshot (exported for the daemon's collector adapter).
type WSMetrics struct {
	ConnectionsActive   uint64
	ConnectionsByResult map[string]uint64
	ReconnectsTotal     uint64
	RxMessages, TxMessages, RxBytes, TxBytes uint64
	DroppedByReason     map[string]uint64
	LastPingRTTSeconds  float64
	PerEndpoint         map[string]WSEndpointMetric // key = DstToString
}

type WSEndpointMetric struct {
	Reconnects     uint64
	PingRTTSeconds float64
}

func (s *wsMetricsState) ensure() {
	if s.connectionsByResult == nil {
		s.connectionsByResult = map[string]uint64{}
		s.droppedByReason = map[string]uint64{}
		s.perEndpoint = map[string]*wsEndpointMetric{}
	}
}

func (s *wsMetricsState) incConn(delta int64, result string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	if delta > 0 {
		s.connectionsActive += uint64(delta)
		s.connectionsByResult[result]++
	} else if s.connectionsActive > 0 {
		s.connectionsActive--
	}
}

func (s *wsMetricsState) incReconnect(endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	s.reconnectsTotal++
	e := s.perEndpoint[endpoint]
	if e == nil {
		e = &wsEndpointMetric{}
		s.perEndpoint[endpoint] = e
	}
	e.reconnects++
}

func (s *wsMetricsState) observeRTT(endpoint string, seconds float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	s.lastPingRTTSeconds = seconds
	e := s.perEndpoint[endpoint]
	if e == nil {
		e = &wsEndpointMetric{}
		s.perEndpoint[endpoint] = e
	}
	e.pingRTTSeconds = seconds
}

func (s *wsMetricsState) addRx(msgs, bytes uint64) { s.mu.Lock(); s.rxMessages += msgs; s.rxBytes += bytes; s.mu.Unlock() }
func (s *wsMetricsState) addTx(msgs, bytes uint64) { s.mu.Lock(); s.txMessages += msgs; s.txBytes += bytes; s.mu.Unlock() }
func (s *wsMetricsState) drop(reason string)       { s.mu.Lock(); s.ensure(); s.droppedByReason[reason]++; s.mu.Unlock() }

func (b *WebSocketBind) WSMetricsSnapshot() WSMetrics {
	s := &b.metrics
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensure()
	out := WSMetrics{
		ConnectionsActive:   s.connectionsActive,
		ConnectionsByResult: map[string]uint64{},
		ReconnectsTotal:     s.reconnectsTotal,
		RxMessages:          s.rxMessages,
		TxMessages:          s.txMessages,
		RxBytes:             s.rxBytes,
		TxBytes:             s.txBytes,
		DroppedByReason:     map[string]uint64{},
		LastPingRTTSeconds:  s.lastPingRTTSeconds,
		PerEndpoint:         map[string]WSEndpointMetric{},
	}
	for k, v := range s.connectionsByResult {
		out.ConnectionsByResult[k] = v
	}
	for k, v := range s.droppedByReason {
		out.DroppedByReason[k] = v
	}
	for k, e := range s.perEndpoint {
		out.PerEndpoint[k] = WSEndpointMetric{Reconnects: e.reconnects, PingRTTSeconds: e.pingRTTSeconds}
	}
	return out
}
```

  Expose the optional interface `WebSocketMetricsProvider interface { WSMetricsSnapshot() WSMetrics }`
  (the daemon type-asserts the bind; `metrics` does NOT import `conn`). Then MODIFY the US2/US4/US6
  code paths to call `b.metrics.incConn/incReconnect/observeRTT/addRx/addTx/drop` at: successful dial
  (`incConn(+1,"ok")`)/dial error (`incConn(0,"dial_error")`); read-loop exit (`incConn(-1,...)`);
  reconnect (`incReconnect(ep.DstToString())`); each delivered/sent message (`addRx`/`addTx`);
  oversize/queue-full drop (`drop`); ping RTT (`observeRTT`).

### [ ] Task 8.3 — Metrics package + listener
- [ ] **Action 8.3.1** — modify `go.mod`: add `github.com/prometheus/client_golang v1.24.1`;
  `go mod tidy`. (`deps` scope.)
- [ ] **Action 8.3.2** — create `metrics/collector.go`: the `metrics` package owns its OWN DTOs and
  takes a single `snapshot func() Snapshot` supplied by the daemon — so `metrics` imports neither
  `device` nor `conn`, and neither imports `metrics` (no cross-package structural typing, no import
  cycle). `Collector` implements `Describe` (via `prometheus.DescribeByCollect`) and `Collect`
  (scrape-time `MustNewConstMetric` over one `snapshot()`).

```go
package metrics

import "github.com/prometheus/client_golang/prometheus"

type PeerStat struct {
	PublicKey         [32]byte
	Endpoint          string
	TxBytes, RxBytes  uint64
	LastHandshakeNano int64
	Connected         bool
	Reconnects        uint64  // per-peer, joined from WS per-endpoint stats (0 for UDP)
	PingRTTSeconds    float64 // per-peer, 0 if unknown
}

type Snapshot struct {
	Peers                                                    []PeerStat
	HandshakeRateLimited, HandshakesCompleted, HandshakesFailed uint64
	HasWS                                                    bool
	WSConnectionsActive, WSReconnectsTotal                   uint64
	WSConnectionsByResult, WSDroppedByReason                 map[string]uint64
	WSRxMessages, WSTxMessages, WSRxBytes, WSTxBytes         uint64
	WSPingRTTSeconds                                         float64
}

type Collector struct {
	snapshot func() Snapshot
	// high-level
	info, peers, hsRateLimited, hsTotal                                        *prometheus.Desc
	wsConnActive, wsConnTotal, wsReconnects, wsDropped, wsPingRTT              *prometheus.Desc
	wsRxMsgs, wsTxMsgs, wsRxBytes, wsTxBytes                                    *prometheus.Desc
	// per-peer (label: peer)
	peerTx, peerRx, peerLastHS, peerConnected, peerReconnects, peerPingRTT      *prometheus.Desc
}

func NewCollector(snapshot func() Snapshot) *Collector {
	d := func(n, h string, labels ...string) *prometheus.Desc { return prometheus.NewDesc(n, h, labels, nil) }
	return &Collector{
		snapshot:       snapshot,
		info:           d("wireguard_info", "Static info", "version"),
		peers:          d("wireguard_peers", "Configured peers"),
		hsRateLimited:  d("wireguard_handshake_rate_limited_total", "Rate-limited handshakes"),
		hsTotal:        d("wireguard_handshakes_total", "Handshakes by result", "result"),
		wsConnActive:   d("wireguard_ws_connections_active", "Active WS connections"),
		wsConnTotal:    d("wireguard_ws_connections_total", "WS connections by result", "result"),
		wsReconnects:   d("wireguard_ws_reconnects_total", "WS reconnects"),
		wsDropped:      d("wireguard_ws_dropped_messages_total", "Dropped WS messages", "reason"),
		wsPingRTT:      d("wireguard_ws_ping_rtt_seconds", "Last WS ping RTT"),
		wsRxMsgs:       d("wireguard_ws_rx_messages_total", "WS rx messages"),
		wsTxMsgs:       d("wireguard_ws_tx_messages_total", "WS tx messages"),
		wsRxBytes:      d("wireguard_ws_rx_bytes_total", "WS rx bytes"),
		wsTxBytes:      d("wireguard_ws_tx_bytes_total", "WS tx bytes"),
		peerTx:         d("wireguard_peer_tx_bytes_total", "Per-peer tx bytes", "peer"),
		peerRx:         d("wireguard_peer_rx_bytes_total", "Per-peer rx bytes", "peer"),
		peerLastHS:     d("wireguard_peer_last_handshake_timestamp_seconds", "Per-peer last handshake", "peer"),
		peerConnected:  d("wireguard_peer_connected", "Per-peer connected (1/0)", "peer"),
		peerReconnects: d("wireguard_peer_reconnects_total", "Per-peer WS reconnects", "peer"),
		peerPingRTT:    d("wireguard_peer_ping_rtt_seconds", "Per-peer WS ping RTT", "peer"),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) { prometheus.DescribeByCollect(c, ch) }

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	s := c.snapshot()
	cv := func(desc *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, v, labels...)
	}
	gv := func(desc *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v, labels...)
	}
	gv(c.info, 1, version())
	gv(c.peers, float64(len(s.Peers)))
	cv(c.hsRateLimited, float64(s.HandshakeRateLimited))
	cv(c.hsTotal, float64(s.HandshakesCompleted), "completed")
	cv(c.hsTotal, float64(s.HandshakesFailed), "failed")
	if s.HasWS {
		gv(c.wsConnActive, float64(s.WSConnectionsActive))
		for r, n := range s.WSConnectionsByResult {
			cv(c.wsConnTotal, float64(n), r)
		}
		cv(c.wsReconnects, float64(s.WSReconnectsTotal))
		for r, n := range s.WSDroppedByReason {
			cv(c.wsDropped, float64(n), r)
		}
		gv(c.wsPingRTT, s.WSPingRTTSeconds)
		cv(c.wsRxMsgs, float64(s.WSRxMessages))
		cv(c.wsTxMsgs, float64(s.WSTxMessages))
		cv(c.wsRxBytes, float64(s.WSRxBytes))
		cv(c.wsTxBytes, float64(s.WSTxBytes))
	}
	for _, p := range s.Peers {
		key := peerLabel(p.PublicKey)
		cv(c.peerTx, float64(p.TxBytes), key)
		cv(c.peerRx, float64(p.RxBytes), key)
		gv(c.peerLastHS, float64(p.LastHandshakeNano)/1e9, key)
		connected := 0.0
		if p.Connected {
			connected = 1
		}
		gv(c.peerConnected, connected, key)
		cv(c.peerReconnects, float64(p.Reconnects), key)
		gv(c.peerPingRTT, p.PingRTTSeconds, key)
	}
}

// version() and peerLabel() live in metrics/util.go: version returns the build
// version string (injected by the daemon via a package var), peerLabel base64-
// encodes the 32-byte key (WireGuard's canonical peer identifier).
```
- [ ] **Action 8.3.3** — create `metrics/server.go` and `metrics/util.go`.

```go
// metrics/server.go
package metrics

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Serve runs a /metrics listener until ctx is cancelled. Blocks; run in a goroutine.
func Serve(ctx context.Context, addr string, reg *prometheus.Registry) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
```

```go
// metrics/util.go
package metrics

import "encoding/base64"

// Version is set by the daemon (main) to the build version before registration.
var Version = "dev"

func version() string { return Version }

func peerLabel(pk [32]byte) string { return base64.StdEncoding.EncodeToString(pk[:]) }
```
- [ ] **Action 8.3.4** — modify `main.go`: if `WG_METRICS_LISTEN` is set, build the
  `snapshot func() metrics.Snapshot` closure and register `metrics.NewCollector(snapshot)`, then start
  `metrics.Serve` in a goroutine with a shutdown path. The closure, at scrape time: (a) calls
  `dev.IterPeerStats` and `dev.HandshakeStats`; (b) if `bind` implements
  `conn.WebSocketMetricsProvider`, calls `WSMetricsSnapshot()` and sets `HasWS=true`; (c) maps
  `device.PeerStats`→`metrics.PeerStat`, joining each peer's WS per-endpoint `Reconnects`/`PingRTTSeconds`
  by matching `PeerStat.Endpoint` to the WS snapshot's per-endpoint map key. This is the sole place
  `device` and `conn` snapshots meet; `metrics` stays decoupled. Empty `WG_METRICS_LISTEN` ⇒ metrics
  OFF (no listener).

**Metric set (D15):** high-level — `wireguard_info`, `wireguard_peers`,
`wireguard_ws_connections_active`, `wireguard_ws_connections_total{result}`,
`wireguard_ws_reconnects_total`, `wireguard_ws_rx_messages_total`, `wireguard_ws_tx_messages_total`,
`wireguard_ws_rx_bytes_total`, `wireguard_ws_tx_bytes_total`,
`wireguard_ws_dropped_messages_total{reason}`, `wireguard_ws_ping_rtt_seconds`,
`wireguard_handshake_rate_limited_total`, `wireguard_handshakes_total{result=completed|failed}`;
per-peer `peer=<pubkey>` — `wireguard_peer_tx_bytes_total`, `wireguard_peer_rx_bytes_total`,
`wireguard_peer_last_handshake_timestamp_seconds`, `wireguard_peer_connected`,
`wireguard_peer_reconnects_total`, `wireguard_peer_ping_rtt_seconds`.

### [ ] Task 8.4 — US8 tests
- [ ] **Action 8.4.1** — create `metrics/collector_test.go`, `metrics/server_test.go`,
  `device/stats_test.go`.

| Test | Verifies |
|---|---|
| `TestCollector_Output` | a seeded `Snapshot` (peers + `HasWS=true` WS fields, per-peer reconnects/rtt joined) produces the expected metric families/values (parse via `promhttp` scrape). |
| `TestCollector_NoWS` | `Snapshot{HasWS:false}` emits device/peer metrics only, no WS families, no panic. |
| `TestCollector_PerPeerJoin` | per-peer `reconnects`/`ping_rtt` come through from the joined per-endpoint WS stats, keyed by `PeerStat.Endpoint`. |
| `TestCollector_LabelCardinality` | per-peer labels bounded to the snapshot's peers; no unbounded label. |
| `TestMetricsServer_OffByDefault` | no listener when addr empty; listener serves `/metrics` when set. |
| `TestDevice_IterPeerStats` | snapshot matches seeded peer atomics; taken under RLock (no race). |
| `TestDevice_HandshakeCounters` | rate-limited/completed/failed increment at the hooks. |

- [ ] **DoD Task 8.4:** pass with `-race`.

**US8 DoD:** metrics scrape at both levels; default build exposes nothing until configured.

---

## [ ] US9 — Mobile integration surfaces (Android/macOS) (P9)

**Why:** Expose exactly the Layer-A contract `docs/ANDROID_INTEGRATION.md` requires — a per-dial
protect callback and a compilable mobile build — with NO new bump API (`BindUpdate` already exists).
Depends on: US5, US6.

**Acceptance criteria:**
- [ ] The WS client bind builds for Android (`GOOS=android`) and macOS (`GOOS=darwin`) targets — the
      delivery target of WORK_PLAN §1 (the official WireGuard macOS/Android apps). iOS is NOT a target;
      the build-tag partition still resolves cleanly for `GOOS=ios` (it implies `darwin`) so the base
      library's existing iOS build is not broken, but no iOS work is in scope.
- [ ] Every dial invokes the `func(fd int)` protect callback (already added in US5) before use.
- [ ] The WS bind does NOT implement `conn.PeekLookAtSocketFd`; `wgGetSocketV4/V6`-style callers get
      `-1` behavior (bind simply lacks the method). No AAR is produced by this repo (D18).

### [ ] Task 9.1 — Verify + lock the mobile contract
- [ ] **Action 9.1.1** — add a compile-time assertion in `conn/ws_bind.go` (a test, Task 9.2) that
  `*WebSocketBind` does NOT satisfy `conn.PeekLookAtSocketFd` and DOES accept `WithWSProtect`.
- [ ] **Action 9.1.2** — confirm no cgo is required for the Android build: the Linux/Android pinning
  path uses `SO_MARK` (pure syscall, US5); the darwin cgo path is `darwin`-only. Android uses the
  protect callback for socket protection, not `SO_MARK` binding to a physical iface (unprivileged app)
  — the callback is the delivery. Verified: no repo change needed for the bump (`BindUpdate` exported).
- [ ] **Action 9.1.3** — verify `conn` compiles under `GOOS=android` and `GOOS=darwin` (the mobile
  targets). The path-monitor build tags MUST already partition these correctly per US5 Actions
  5.2.2/5.2.4 (netlink = `linux && !android`; no-op = `(!linux && !darwin) || android`; darwin cgo =
  `darwin && cgo`). In Go, `GOOS=android` satisfies `linux` (so it lands on the no-op via the
  `|| android` term, NOT the netlink file). `GOOS=ios` — though not a target — satisfies `darwin` and
  therefore resolves to the same darwin file set (cgo NWPathMonitor with cgo on, else the
  `darwin && !cgo` no-op), so the base library's iOS build stays intact. This action does NOT re-tag
  anything — it asserts the US5 tags are coherent; if any target fails to compile with exactly one
  `newWSPathMonitor`, fix the US5 tags and record it in `## Deviations`.

### [ ] Task 9.2 — US9 tests + build check
- [ ] **Action 9.2.1** — create `conn/ws_mobile_test.go`.

| Test | Verifies |
|---|---|
| `TestWSBind_NotPeekLookAtSocketFd` | `*WebSocketBind` does not satisfy `conn.PeekLookAtSocketFd`. |
| `TestWSBind_ProtectOption` | `WithWSProtect` stored; invoked per dial (reuses US5 fake control). |

- [ ] **Action 9.2.2** — the CI mobile compile-check job (US10) is the build-target gate:
  `GOOS=android GOARCH={arm64,arm,amd64} CGO_ENABLED=0 go build ./...` on Linux. macOS is covered by
  the CI darwin build check. No AAR (D18).

**US9 DoD:** the WS client bind builds for Android/macOS targets and every dial is protectable.

---

## [ ] US10 — Packaging & delivery: goreleaser, Docker/ghcr, CI/CD, Makefile (P10)

**Why:** Ship multi-platform binaries + multi-arch images to `ghcr.io/danielealbano/wireguard-go` and
enforce the quality gates on every PR/push. Depends on: US3, US7, US8, US9.

**Acceptance criteria:**
- [ ] `goreleaser release --snapshot --clean` produces binaries + a local multi-arch image; the image
      runs `wireguard-go --version`.
- [ ] Tagging `vX.Y.Z` publishes binaries + checksums and a multi-arch image to the user's ghcr.
- [ ] CI (build, `go vet`, `golangci-lint`, `-race` tests, `go mod tidy` diff-check, `govulncheck`,
      `mermaid-check`, Android compile-check) is green on PRs/pushes.

### [ ] Task 10.1 — Makefile alignment (project.md Standard Commands)
- [ ] **Action 10.1.1** — modify `Makefile`: keep `all`/`install`/`clean`/`generate-version-and-build`;
  add the targets below (matching `project.md`). Append to the existing `.PHONY`.

```makefile
vet:
	go vet ./...

lint:
	golangci-lint run

lint-fix:
	golangci-lint run --fix

test:
	go test -race ./...

test-e2e: wireguard-go
	./tests/netns.sh ./wireguard-go

test-all: test test-e2e

tidy:
	go mod tidy

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

mermaid-check:
	./scripts/mermaid-check.sh docs

snapshot:
	goreleaser release --snapshot --clean

release:
	goreleaser release --clean

.PHONY: vet lint lint-fix test test-e2e test-all tidy vulncheck mermaid-check snapshot release
```

  `test-e2e` needs Linux + privileges (`tests/netns.sh`).
- [ ] **Action 10.1.2** — create `scripts/mermaid-check.sh` (walks a directory and validates every
  Mermaid block in every `*.md` under it, per development_pipeline §9). Make it executable.

```bash
#!/usr/bin/env bash
set -uo pipefail

DIR="${1:-docs}"
# Load nvm if present (so npx/node are on PATH); ignore if unavailable.
[ -n "${NVM_DIR:-}" ] && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

fail=0
while IFS= read -r -d '' md; do
  if ! python3 - "$md" <<'PY'
import re, subprocess, sys, json, tempfile, os
puppet = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
json.dump({'args': ['--no-sandbox']}, puppet); puppet.close()
content = open(sys.argv[1]).read()
blocks = re.findall(r'```mermaid\n(.*?)\n```', content, re.DOTALL)
bad = False
for i, block in enumerate(blocks):
    mmd = f'/tmp/mmc_{os.getpid()}_{i}.mmd'
    with open(mmd, 'w') as f:
        f.write(block)
    r = subprocess.run(
        ['npx', '--yes', '@mermaid-js/mermaid-cli', '-p', puppet.name,
         '-i', mmd, '-o', f'/tmp/mmc_{os.getpid()}_{i}.svg'],
        capture_output=True, text=True, timeout=90)
    if r.returncode != 0:
        bad = True
        sys.stderr.write(f'{sys.argv[1]} chart {i}: FAILED\n{r.stderr[:500]}\n')
os.unlink(puppet.name)
sys.exit(1 if bad else 0)
PY
  then
    fail=1
  fi
done < <(find "$DIR" -name '*.md' -print0)

exit "$fail"
```

### [ ] Task 10.2 — Container image
> **Deviation (see `## Deviations`): `builder: prebuilt` is goreleaser PRO, not OSS.** Task 10.2/10.3/10.4
> below reflect the OSS-only approach actually built: a self-contained multi-stage `Dockerfile`, a single
> `.goreleaser.yaml` (run on macOS) for all binaries, and a separate Linux `docker/build-push-action`
> job for the multi-arch image. No `.goreleaser.darwin.yaml`.

- [ ] **Action 10.2.1** — create `Dockerfile` (self-contained multi-stage; buildx cross-compiles the
  linux binary per target arch with CGO disabled).

```dockerfile
FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS build
WORKDIR /src
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /wireguard-go .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /wireguard-go /usr/bin/wireguard-go
ENTRYPOINT ["/usr/bin/wireguard-go"]
```

### [ ] Task 10.3 — goreleaser
- [ ] **Action 10.3.1** — create `.goreleaser.yaml` (v2), run on the **macOS** runner in a single
  invocation. Two `builds`: darwin `CGO_ENABLED=1` (native NWPathMonitor cgo) and the
  linux/windows/bsd targets cross-compiled `CGO_ENABLED=0`; `archives` + unified `checksums.txt`. NO
  `dockers`/`docker_manifests` (the image is built by the Linux job, Action 10.4.2).

```yaml
version: 2
project_name: wireguard-go
builds:
  - id: native
    main: .
    binary: wireguard-go
    env: [CGO_ENABLED=0]
    goos: [linux, windows, freebsd, openbsd]
    goarch: [amd64, arm64]
    flags: [-trimpath]
    ldflags: ["-s -w"]
  - id: darwin
    main: .
    binary: wireguard-go
    env: [CGO_ENABLED=1]
    goos: [darwin]
    goarch: [amd64, arm64]
    flags: [-trimpath]
    ldflags: ["-s -w"]
archives:
  - id: default
    ids: [native, darwin]
    formats: [tar.gz]
    format_overrides:
      - goos: windows
        formats: [zip]
checksum:
  name_template: "checksums.txt"
```

- [ ] **Action 10.3.2** — (removed) — a single `.goreleaser.yaml` now covers all binaries; there is no
  separate darwin config and no prebuilt import.
- [ ] **Action 10.3.3** — verify locally: `goreleaser check` validates the config; `goreleaser build
  --snapshot --clean` builds the binaries (Manual QA).

### [ ] Task 10.4 — GitHub Actions
- [ ] **Action 10.4.1** — create `.github/workflows/ci.yml`.

```yaml
name: CI
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.1
      - uses: actions/setup-go@v7.0.0
        with:
          go-version: stable
      - run: go build ./...
      - run: go vet ./...
      - uses: golangci/golangci-lint-action@v9.3.0
        with:
          version: v2.12.2
      - run: go test -race ./...
      - run: go mod tidy && git diff --exit-code go.mod go.sum
      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
  mermaid:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.1
      - run: ./scripts/mermaid-check.sh docs
  android:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.1
      - uses: actions/setup-go@v7.0.0
        with:
          go-version: stable
      - run: |
          for arch in arm64 arm amd64; do
            GOOS=android GOARCH=$arch CGO_ENABLED=0 go build ./...
          done
  darwin:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v7.0.1
      - uses: actions/setup-go@v7.0.0
        with:
          go-version: stable
      - run: CGO_ENABLED=1 go build ./...
```

- [ ] **Action 10.4.2** — create `.github/workflows/release.yml`: two PARALLEL jobs (standard macOS
  runners are free for public repos, verified) — `binaries` on macOS (single goreleaser run: all
  binaries + checksums + GitHub release) and `image` on Linux (`docker/build-push-action` multi-arch
  build+push to ghcr from the self-contained `Dockerfile`).

```yaml
name: Release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
  packages: write
jobs:
  binaries:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v7.0.1
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v7.0.0
        with:
          go-version: stable
      - uses: goreleaser/goreleaser-action@v7.2.3
        with:
          version: "~> v2"
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.1
      - uses: docker/setup-qemu-action@v4.2.0
      - uses: docker/setup-buildx-action@v4.2.0
      - uses: docker/login-action@v4.6.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v7.3.0
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          tags: |
            ghcr.io/danielealbano/wireguard-go:${{ github.ref_name }}
            ghcr.io/danielealbano/wireguard-go:latest
```

  `upload-artifact`/`download-artifact` are pinned to the current `v4` major; the artifact preserves
  the `wireguard-go_darwin_<arch>/wireguard-go` layout the Linux job's `prebuilt.path` expects.

### [ ] Task 10.5 — US10 tests / gates
- [ ] **Action 10.5.1** — CI itself is the test surface (no Go unit test). Manual QA: a `snapshot`
  build + `docker run …:latest-<arch> --version`.

**US10 DoD:** tagging publishes binaries + checksums + a multi-arch ghcr image; CI enforces the gates.

---

## [ ] US11 — Documentation + full ground-up verification (final)

**Why:** Keep the canonical docs and `project.md` current, and double-check EVERYTHING from the ground
up (pipeline requires the last item to verify the whole plan). Depends on: US1–US10.

### [ ] Task 11.1 — Documentation
- [ ] **Action 11.1.1** — modify `docs/PROJECT.md`: WS transport in the tech-stack + roadmap→shipped;
  new env vars (`WG_TRANSPORT`, `WG_WS_*`, `WG_METRICS_LISTEN`) in the env table; new UAPI keys.
- [ ] **Action 11.1.2** — modify `docs/ARCHITECTURE.md`: add a WS-transport section with ONE Mermaid
  chart of the WS outbound/inbound path at the `conn.Bind` seam (client + server). (Adds a Mermaid
  chart ⇒ triggers the Mermaid validation step below.)
- [ ] **Action 11.1.3** — modify `.claude/rules/project.md`: add WS env vars/UAPI keys note, the
  `metrics` scope? — NO new commit scope needed (`conn` covers the bind; `core` covers cross-cutting;
  `docs`/`ci`/`make` exist). Confirm the Standard Commands match the new Makefile targets.
- [ ] **Action 11.1.4** — update `docs/WORK_PLAN.md` phase checkboxes are NOT present there; leave it
  as the decisions record (no checkmarks). Do NOT duplicate the plan into it.

### [ ] Task 11.2 — Ground-up double-check (whole plan)
- [ ] **Action 11.2.1** — re-read this plan top to bottom; confirm every action landed and every
  acceptance criterion is checked.
- [ ] **Action 11.2.2** — run the FULL quality gates via the project commands (ONLY here, never
  per-task — pipeline §6): `make vet`, `make lint`, `make build`/`go build ./...`,
  `make test` (`-race`), `make tidy` (assert NO `go.mod`/`go.sum` diff), `make vulncheck`. Capture
  each long run through `tee` to `/tmp/wireguard-go-<gate>.log` (agent.md §5).
- [ ] **Action 11.2.3** — cross-platform compile matrix: `GOOS in {linux,darwin,windows,freebsd,openbsd}`
  (`go build ./...`) + `GOOS=android` (arm64/arm/amd64, `CGO_ENABLED=0`) + `GOOS=darwin` (arm64) with
  `CGO_ENABLED=1` on the macOS host (cgo NWPathMonitor path). Each build-tag combination must resolve
  to exactly one `newWSPathMonitor` (a `GOOS=ios` spot-check confirms the base library's iOS build is
  not broken, though iOS is not a target).
- [ ] **Action 11.2.4** — **Mermaid validation (REQUIRED — Task 11.1.2 adds a chart):** run
  `make mermaid-check` (development_pipeline §9) over `docs/`; ZERO failures.
- [ ] **Action 11.2.5** — confirm invariants (WORK_PLAN §6): no wire-protocol/constant change
  (`device/constants.go` untouched); device core has no transport-specific logic beyond optional
  interface type-asserts; no secret in any log/`IpcGet`; single bind per device preserved.

**US11 DoD:** docs current; all gates green; all platforms compile; Mermaid valid; invariants hold.

---

## Manual QA (NOT automated — documented per go.md)

- **Wstunnel interop (US3):** with `WG_TRANSPORT=ws`, `ws_mode=wstunnel`, the peer `endpoint` = the
  live wstunnel server URL and `ws_target` = the real WireGuard endpoint, tunnel real traffic both
  ways using the user's existing `~/Downloads` config (the implementer MUST NOT open or print that
  file — it contains a private key); the wstunnel pre/post wrapper scripts are removed once
  integrated. Confirms `101` + data flow + masking.
- **Egress pinning / path re-pin (US5):** on macOS and Linux, with the default route over the tun,
  confirm the WS transport still egresses via the physical link and reconnects on a Wi-Fi⇄cellular /
  interface switch.
- **Packaging (US10):** `make snapshot`; `docker run ghcr.io/danielealbano/wireguard-go:latest-<arch> --version`.

## Deviations

(Recorded during implementation per agent.md §2.)

- **Action 1.4.3 — `handlePostConfig` signature change (foreseen):** `ipcSetPeer.handlePostConfig()`
  now returns `error` (was void) so a WebSocket-endpoint build failure surfaces through
  `IpcSetOperation`. Propagated at all three call sites (`device/uapi.go` blank-line terminate,
  `public_key` line, end-of-scan).
- **P10 packaging — `builder: prebuilt` is goreleaser PRO, not OSS (plan claim corrected).** The plan
  (and WORK_PLAN) assumed goreleaser's `prebuilt` builder was OSS. Verified against goreleaser v2.17.1:
  the OSS `Build.Builder` enum is `go,rust,zig,bun,deno,node,uv,poetry` (no `prebuilt`), and the
  prebuilt builder is documented only in `schema-pro.json`/`pro.md`. The two-job "prebuilt import"
  approach is therefore not available in OSS. **Replaced with an OSS-only design:** a single
  `.goreleaser.yaml` (run on the macOS runner) builds ALL binaries — the darwin targets with
  `CGO_ENABLED=1` (native NWPathMonitor cgo) and the linux/windows/bsd targets cross-compiled with
  `CGO_ENABLED=0` — plus archives, a unified `checksums.txt`, and the GitHub release; a separate,
  parallel Linux job builds and pushes the multi-arch container image via `docker/build-push-action`
  (a self-contained multi-stage `Dockerfile`), so buildx runs on Linux as required.
  `.goreleaser.darwin.yaml` is removed (a single config now covers all binaries).
- **`SetWSListen` + server `listenURL` synchronization (US1/US6).** `cfg.listenURL` is mutated by
  `SetWSListen` (a `ws_listen=` UAPI line triggers `BindUpdate`) and read by `openServer`, which can run
  concurrently. `SetWSListen` now writes it under `b.mu`, and `openServer` (called from `Open` under
  `b.mu`) snapshots it into a local so the serve goroutine never touches the field. `-race` clean.
- **Darwin egress pinning skips loopback (US5).** The darwin `dialControl` skips `IP_BOUND_IF` for
  loopback destinations (`wsIsLoopback` in `conn/ws_iface_darwin.go`): pinning a loopback dial to the
  physical egress interface makes the connect fail (`can't assign requested address`). This is correct
  in production (loopback never loops into the tun) and is required for the loopback tunnel tests.
- **CI Android job compiles the library packages, not `./...` (US9/US10).** An android executable for
  `arm`/`amd64` requires external cgo linking; since Android consumes this repo as a Go module (no
  standalone daemon, D18), the `android` CI job compile-checks the library packages and excludes the
  root `main` package.
- **Implementation: final code written directly (no stub/replace sequence).** The plan sequenced US1
  with compiling `Open`/`Close`/`Send` stubs in `ws_bind.go` that US2/US6 would replace. Since the
  implementation builds once at the end (quality gates), the final files were written directly: the
  real `Open`/`Close`/`Send` live in `ws_client.go`, `ws_bind.go` carries only the struct + parse/config
  methods, and the metrics/increment wiring is present from the start rather than added as a later
  modify. Behaviour is identical to the plan's final state.
