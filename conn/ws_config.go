/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net/netip"
	"time"
)

// Logger is the minimal logging surface the WebSocket bind needs, modeled as func
// fields (not an interface) to mirror device.Logger, whose Verbosef/Errorf are func
// fields rather than methods. conn does not import device; the daemon builds this
// from *device.Logger. A nil field means that level is silent.
type Logger struct {
	Verbosef func(format string, args ...any)
	Errorf   func(format string, args ...any)
}

func (l Logger) verbosef(format string, args ...any) {
	if l.Verbosef != nil {
		l.Verbosef(format, args...)
	}
}

func (l Logger) errorf(format string, args ...any) {
	if l.Errorf != nil {
		l.Errorf(format, args...)
	}
}

const (
	wsDefaultPingInterval = 25 * time.Second
	wsDefaultBackoffMin   = 500 * time.Millisecond
	wsDefaultBackoffMax   = 30 * time.Second
	// wsReadLimit caps a single inbound WebSocket message. 1<<16 covers the largest
	// device receive buffer (MaxSegmentSize) on every platform; the exact per-message
	// guard is len(callerBuffer) at delivery time.
	wsReadLimit = 1 << 16
)

// wsConfig holds the device/listener-level WebSocket settings. Per-peer client
// settings (ws_url, TLS, mask, timings) live on WSEndpoint, not here. Server/
// listener settings arrive via the device-level UAPI setters, not env.
type wsConfig struct {
	listenURL      string
	serverCertPath string // ws_server_tls_cert; loaded at openServer
	serverKeyPath  string // ws_server_tls_key
	serverBearer   string // expected Bearer (coarse gate); empty = gate off. NEVER logged.
	trustedProxies []netip.Prefix
	protect        func(fd int)
	logger         Logger
}

// WSOption configures a WebSocketBind (functional options). Only the construction-
// time dependencies remain as options; all tunnel config arrives via the UAPI.
type WSOption func(*wsConfig) error

func WithWSProtect(fn func(fd int)) WSOption {
	return func(c *wsConfig) error { c.protect = fn; return nil }
}

func WithWSLogger(l Logger) WSOption { return func(c *wsConfig) error { c.logger = l; return nil } }
