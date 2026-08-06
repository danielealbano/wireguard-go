/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"os"

	"github.com/prometheus/client_golang/prometheus"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/metrics"
)

// newDaemonBind builds the daemon's transport bind: a multiplexing bind that
// carries UDP and WebSocket/wstunnel peers at once. All tunnel config (per-peer
// transport, endpoints, TLS, server/listener settings) now arrives via the UAPI,
// so only the logger (and, on embedded builds, a protect callback) is wired here.
func newDaemonBind(logger *device.Logger) (conn.Bind, error) {
	return conn.NewMultiplexBind(
		conn.WithWSLogger(conn.Logger{Verbosef: logger.Verbosef, Errorf: logger.Errorf}),
	)
}

// startMetrics starts the Prometheus listener if WG_METRICS_LISTEN is set and
// returns a cancel func (always non-nil; a no-op when metrics are off).
func startMetrics(logger *device.Logger, dev *device.Device, bind conn.Bind) context.CancelFunc {
	addr := os.Getenv("WG_METRICS_LISTEN")
	if addr == "" {
		return func() {}
	}
	metrics.Version = Version
	wsProvider, _ := bind.(conn.WebSocketMetricsProvider)
	collector := metrics.NewCollector(func() metrics.Snapshot {
		return wsMetricsSnapshot(dev, wsProvider)
	})
	reg := prometheus.NewRegistry()
	reg.MustRegister(collector)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := metrics.Serve(ctx, addr, reg); err != nil {
			logger.Errorf("Metrics listener error: %v", err)
		}
	}()
	logger.Verbosef("Metrics listener started on %s", addr)
	return cancel
}

// wsMetricsSnapshot is the single place device and conn snapshots meet; it maps
// them into the decoupled metrics DTOs, joining per-peer WS stats by endpoint.
func wsMetricsSnapshot(dev *device.Device, ws conn.WebSocketMetricsProvider) metrics.Snapshot {
	var s metrics.Snapshot
	var perEndpoint map[string]conn.WSEndpointMetric
	if ws != nil {
		m := ws.WSMetricsSnapshot()
		s.HasWS = true
		s.WSConnectionsActive = m.ConnectionsActive
		s.WSConnectionsByResult = m.ConnectionsByResult
		s.WSReconnectsTotal = m.ReconnectsTotal
		s.WSRxMessages = m.RxMessages
		s.WSTxMessages = m.TxMessages
		s.WSRxBytes = m.RxBytes
		s.WSTxBytes = m.TxBytes
		s.WSDroppedByReason = m.DroppedByReason
		s.WSPingRTTSeconds = m.LastPingRTTSeconds
		perEndpoint = m.PerEndpoint
	}
	dev.IterPeerStats(func(p device.PeerStats) {
		ps := metrics.PeerStat{
			PublicKey:         p.PublicKey,
			Endpoint:          p.Endpoint,
			TxBytes:           p.TxBytes,
			RxBytes:           p.RxBytes,
			LastHandshakeNano: p.LastHandshakeNano,
			Connected:         p.Connected,
		}
		if e, ok := perEndpoint[p.Endpoint]; ok {
			ps.Reconnects = e.Reconnects
			ps.PingRTTSeconds = e.PingRTTSeconds
		}
		s.Peers = append(s.Peers, ps)
	})
	rateLimited, completed, failed := dev.HandshakeStats()
	s.HandshakeRateLimited = rateLimited
	s.HandshakesCompleted = completed
	s.HandshakesFailed = failed
	return s
}
