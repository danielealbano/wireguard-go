/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// WebSocketBind tunnels the WireGuard wire protocol over ws:// / wss:// instead of
// UDP, in client or server role (selected by cfg.role at construction).
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
	conn   *websocket.Conn
	writeM sync.Mutex
	ep     *WSEndpoint
	ctx    context.Context    // per-connection; derived from the open ctx, cancelled on drop/close
	cancel context.CancelFunc // stops this conn's read loop + ping ticker
}

type wsServerConn struct {
	conn   *websocket.Conn
	writeM sync.Mutex
	id     uint64
	ctx    context.Context // captured at accept from the open ctx
}

type wsBackoff struct {
	until time.Time
	d     time.Duration
}

// WebSocketBinder is type-asserted by the device UAPI handler to build WebSocket
// peer endpoints and set the server listen URL from the additive UAPI keys,
// mirroring how conn.PeekLookAtSocketFd is type-asserted elsewhere. It keeps the
// WebSocket specifics out of the device core.
type WebSocketBinder interface {
	SetWSListen(rawURL string) error
	ParseWSPeerEndpoint(rawURL, mode, target, bearer string) (Endpoint, error)
}

var (
	_ Bind            = (*WebSocketBind)(nil)
	_ WebSocketBinder = (*WebSocketBind)(nil)
)

// NewWebSocketBind constructs a WebSocket bind from functional options.
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
	// Guarded by b.mu because openServer reads cfg.listenURL under b.mu (via Open),
	// and BindUpdate can run Open concurrently with this UAPI write.
	b.mu.Lock()
	b.cfg.listenURL = rawURL
	b.mu.Unlock()
	return nil
}
