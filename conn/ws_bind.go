/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// WebSocketBind tunnels the WireGuard wire protocol over ws:// / wss:// instead of
// UDP. It has no fixed role: it listens whenever ws_listen is configured AND dials
// out to any peer that carries a ws_url, both at once — mirroring UDP's single
// socket that both listens on listen_port and sends to peer endpoints.
//
// All fields (client + server) are declared here; the client/server methods that
// populate them live in ws_client.go / ws_server.go.
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

	metrics wsMetricsState
}

type wsInbound struct {
	data []byte
	ep   *WSEndpoint
}

type wsClientConn struct {
	wc     *wsConn
	ep     *WSEndpoint
	ctx    context.Context    // per-connection; derived from the open ctx, cancelled on drop/close
	cancel context.CancelFunc // stops this conn's read loop + ping ticker
	pong   chan struct{}      // buffered(1); read loop signals a received pong to pingLoop
}

type wsServerConn struct {
	wc *wsConn
	id uint64
}

type wsBackoff struct {
	until time.Time
	d     time.Duration
}

// WebSocketBinder is type-asserted by the device UAPI handler to build WebSocket
// peer endpoints and set the device-level server/listener config from the additive
// UAPI keys, mirroring how conn.PeekLookAtSocketFd is type-asserted elsewhere. It
// keeps the WebSocket specifics out of the device core.
type WebSocketBinder interface {
	SetWSListen(rawURL string) error
	ParseWSPeerEndpoint(cfg WSPeerConfig) (Endpoint, error)
	SetServerCertPath(path string)
	SetServerKeyPath(path string)
	SetServerBearer(tok string)
	SetTrustedProxies(p []netip.Prefix)
}

var (
	_ Bind            = (*WebSocketBind)(nil)
	_ WebSocketBinder = (*WebSocketBind)(nil)
)

// WSPeerConfig carries a peer's per-connection WebSocket settings from the UAPI.
// All fields are exported and the dialect is conveyed as the Transport string, so
// the device package can construct it without touching conn internals.
type WSPeerConfig struct {
	Endpoint       netip.AddrPort // resolved ip:port to dial (from endpoint=)
	Transport      string         // "websocket" | "wstunnel"
	URL            string         // ws_url
	WstunnelTarget string
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

// NewWebSocketBind constructs a WebSocket bind from functional options. Tunnel
// config (client per-peer + server/listener) arrives later via the UAPI.
func NewWebSocketBind(opts ...WSOption) (*WebSocketBind, error) {
	var cfg wsConfig
	for _, o := range opts {
		if err := o(&cfg); err != nil {
			return nil, err
		}
	}
	return &WebSocketBind{cfg: cfg}, nil
}

func (b *WebSocketBind) BatchSize() int { return 1 }

// ParseEndpoint satisfies conn.Bind for a plain ip:port (no ws_url). The primary
// WS path is ParseWSPeerEndpoint; in the daemon plain endpoints route to UDP via
// the multiplex bind, so this only serves standalone/library WebSocketBind use.
func (b *WebSocketBind) ParseEndpoint(s string) (Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("invalid websocket endpoint %q: %w", s, err)
	}
	return &WSEndpoint{
		dialTarget:   ap,
		pingInterval: wsDefaultPingInterval,
		backoffMin:   wsDefaultBackoffMin,
		backoffMax:   wsDefaultBackoffMax,
	}, nil
}

// ParseWSPeerEndpoint builds a dialing WSEndpoint from the per-peer UAPI settings.
// The internal dialect is derived from cfg.Transport.
func (b *WebSocketBind) ParseWSPeerEndpoint(cfg WSPeerConfig) (Endpoint, error) {
	if cfg.URL != "" {
		if u, err := url.Parse(cfg.URL); err != nil || (u.Scheme != "ws" && u.Scheme != "wss") {
			return nil, fmt.Errorf("invalid ws_url %q: scheme must be ws or wss", cfg.URL)
		}
	}
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
	e.pingInterval = orDefault(cfg.PingInterval, wsDefaultPingInterval)
	e.backoffMin = orDefault(cfg.BackoffMin, wsDefaultBackoffMin)
	e.backoffMax = orDefault(cfg.BackoffMax, wsDefaultBackoffMax)
	return e, nil
}

// orDefault returns def when d is zero.
func orDefault(d, def time.Duration) time.Duration {
	if d == 0 {
		return def
	}
	return d
}

// SetMark stores the mark for future dials/accepts AND re-applies it to every
// currently-open socket in place, matching UDP's StdNetBind.SetMark (mark_unix.go).
// This is the socket-side half of the wg-quick fwmark contract: the WS TCP socket
// must carry the mark on every segment or the `ip rule not fwmark` rule blackholes
// it under full-tunnel. Best-effort: the store never fails; a live socket that
// cannot be re-marked is logged and gets marked on its next reconnect.
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

func (b *WebSocketBind) SetWSListen(rawURL string) error {
	if _, err := url.Parse(rawURL); err != nil {
		return fmt.Errorf("invalid ws_listen %q: %w", rawURL, err)
	}
	// Guarded by b.mu because openServer reads cfg.listenURL under b.mu (via Open),
	// and BindUpdate can run Open concurrently with this UAPI write.
	b.mu.Lock()
	b.cfg.listenURL = rawURL
	b.mu.Unlock()
	return nil
}

// WSListenURL reports the configured server listen URL (empty when unset), so IpcGet
// can round-trip ws_listen. Read under b.mu to synchronize with SetWSListen.
func (b *WebSocketBind) WSListenURL() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cfg.listenURL
}

// SetServerCertPath / SetServerKeyPath store the server TLS material as paths;
// openServer loads the keypair at Open, so a live serve goroutine reads a local
// config and never b.cfg. Guarded by b.mu (openServer reads under b.mu; BindUpdate
// may run concurrently with the UAPI write). No cross-line buffering is needed.
func (b *WebSocketBind) SetServerCertPath(path string) {
	b.mu.Lock()
	b.cfg.serverCertPath = path
	b.mu.Unlock()
}

func (b *WebSocketBind) SetServerKeyPath(path string) {
	b.mu.Lock()
	b.cfg.serverKeyPath = path
	b.mu.Unlock()
}

func (b *WebSocketBind) SetServerBearer(tok string) {
	b.mu.Lock()
	b.cfg.serverBearer = tok
	b.mu.Unlock()
}

func (b *WebSocketBind) SetTrustedProxies(p []netip.Prefix) {
	b.mu.Lock()
	b.cfg.trustedProxies = p
	b.mu.Unlock()
}

// WSServerTLSPaths / WSServerBearer / WSTrustedProxies report the device-level
// server settings so IpcGet can round-trip them.
func (b *WebSocketBind) WSServerTLSPaths() (cert, key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cfg.serverCertPath, b.cfg.serverKeyPath
}

func (b *WebSocketBind) WSServerBearer() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cfg.serverBearer
}

func (b *WebSocketBind) WSTrustedProxies() []netip.Prefix {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cfg.trustedProxies
}

// WSInUse reports whether the WebSocket transport is actually carrying anything —
// a configured listener or any open connection. The daemon's path monitor uses it
// to avoid reopening a pure-UDP bind on a network change (UDP path unchanged).
func (b *WebSocketBind) WSInUse() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cfg.listenURL != "" || len(b.conns) > 0 || len(b.sconns) > 0
}
