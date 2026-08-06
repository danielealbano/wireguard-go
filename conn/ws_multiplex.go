/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "net/netip"

// multiplexBind composes the platform UDP bind with a WebSocket bind and
// dispatches per peer by endpoint type, so one device can carry UDP and
// WebSocket/wstunnel peers at the same time. The UDP data path is unchanged: it
// is the exact NewDefaultBind() for the platform (WinRingBind on windows,
// StdNetBind elsewhere), and any non-WS endpoint routes straight to it.
//
// The WebSocket sub-bind is ALWAYS opened (its Open only allocates channels/maps
// and starts the HTTP listener when ws_listen is set), so a WS peer added by
// `wg set` after the interface is up is immediately dialable without a re-Open.
type multiplexBind struct {
	udp Bind
	ws  *WebSocketBind
}

var (
	_ Bind            = (*multiplexBind)(nil)
	_ WebSocketBinder = (*multiplexBind)(nil)
)

// NewMultiplexBind builds the daemon bind: the platform UDP bind plus a WebSocket
// bind constructed from the given options (logger/protect).
func NewMultiplexBind(opts ...WSOption) (*multiplexBind, error) {
	ws, err := NewWebSocketBind(opts...)
	if err != nil {
		return nil, err
	}
	return &multiplexBind{udp: NewDefaultBind(), ws: ws}, nil
}

func (m *multiplexBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	udpFns, actualPort, err := m.udp.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wsFns, _, err := m.ws.Open(actualPort)
	if err != nil {
		_ = m.udp.Close()
		return nil, 0, err
	}
	return append(udpFns, wsFns...), actualPort, nil
}

func (m *multiplexBind) Close() error {
	err1 := m.udp.Close()
	err2 := m.ws.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

func (m *multiplexBind) SetMark(mark uint32) error {
	if err := m.udp.SetMark(mark); err != nil {
		return err
	}
	return m.ws.SetMark(mark)
}

// Send dispatches by endpoint concrete type: a *WSEndpoint goes to the WebSocket
// sub-bind, any other endpoint to the platform UDP bind.
func (m *multiplexBind) Send(bufs [][]byte, ep Endpoint) error {
	if _, ok := ep.(*WSEndpoint); ok {
		return m.ws.Send(bufs, ep)
	}
	return m.udp.Send(bufs, ep)
}

// ParseEndpoint parses a plain ip:port into a UDP endpoint. WebSocket peers are
// built via ParseWSPeerEndpoint (the device selects by the peer's transport).
func (m *multiplexBind) ParseEndpoint(s string) (Endpoint, error) {
	return m.udp.ParseEndpoint(s)
}

// BatchSize reports the UDP sub-bind's size so UDP peers keep GSO batching; the
// WebSocket Send loops per frame, and per-peer batches are homogeneous.
func (m *multiplexBind) BatchSize() int { return m.udp.BatchSize() }

// --- WebSocketBinder + get reporters + metrics + path-monitor gate: forward to the WS sub-bind ---

func (m *multiplexBind) SetWSListen(rawURL string) error { return m.ws.SetWSListen(rawURL) }

func (m *multiplexBind) ParseWSPeerEndpoint(cfg WSPeerConfig) (Endpoint, error) {
	return m.ws.ParseWSPeerEndpoint(cfg)
}

func (m *multiplexBind) SetServerCertPath(path string)        { m.ws.SetServerCertPath(path) }
func (m *multiplexBind) SetServerKeyPath(path string)         { m.ws.SetServerKeyPath(path) }
func (m *multiplexBind) SetServerBearer(tok string)           { m.ws.SetServerBearer(tok) }
func (m *multiplexBind) SetTrustedProxies(p []netip.Prefix)   { m.ws.SetTrustedProxies(p) }
func (m *multiplexBind) WSListenURL() string                  { return m.ws.WSListenURL() }
func (m *multiplexBind) WSServerBearer() string               { return m.ws.WSServerBearer() }
func (m *multiplexBind) WSTrustedProxies() []netip.Prefix     { return m.ws.WSTrustedProxies() }
func (m *multiplexBind) WSServerTLSPaths() (cert, key string) { return m.ws.WSServerTLSPaths() }
func (m *multiplexBind) WSInUse() bool                        { return m.ws.WSInUse() }
func (m *multiplexBind) WSMetricsSnapshot() WSMetrics         { return m.ws.WSMetricsSnapshot() }
