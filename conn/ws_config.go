/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"crypto/tls"
	"net/netip"
	"time"
)

// WSRole selects whether the WebSocket bind dials peers (client) or listens for
// incoming connections (server). It is fixed at bind construction.
type WSRole int

const (
	WSRoleClient WSRole = iota
	WSRoleServer
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

// WSOption configures a WebSocketBind (functional options).
type WSOption func(*wsConfig) error

func WithWSRole(r WSRole) WSOption           { return func(c *wsConfig) error { c.role = r; return nil } }
func WithWSClientTLS(t *tls.Config) WSOption { return func(c *wsConfig) error { c.tlsClient = t; return nil } }
func WithWSServerTLS(t *tls.Config) WSOption { return func(c *wsConfig) error { c.tlsServer = t; return nil } }
func WithWSServerBearer(tok string) WSOption { return func(c *wsConfig) error { c.serverBearer = tok; return nil } }
func WithWSListenURL(u string) WSOption      { return func(c *wsConfig) error { c.listenURL = u; return nil } }
func WithWSPingInterval(d time.Duration) WSOption {
	return func(c *wsConfig) error { c.pingInterval = d; return nil }
}
func WithWSTrustedProxies(p []netip.Prefix) WSOption {
	return func(c *wsConfig) error { c.trustedProxies = p; return nil }
}
func WithWSProtect(fn func(fd int)) WSOption { return func(c *wsConfig) error { c.protect = fn; return nil } }
func WithWSLogger(l Logger) WSOption         { return func(c *wsConfig) error { c.logger = l; return nil } }
