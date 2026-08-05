/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package metrics exposes wireguard-go device and WebSocket-transport metrics as a
// Prometheus collector. It owns its own DTOs and takes a snapshot function supplied
// by the daemon, so it imports neither the device nor conn packages.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// PeerStat is a per-peer metrics DTO. Reconnects/PingRTTSeconds are joined by the
// daemon from the WebSocket per-endpoint stats (0 for the UDP transport).
type PeerStat struct {
	PublicKey         [32]byte
	Endpoint          string
	TxBytes           uint64
	RxBytes           uint64
	LastHandshakeNano int64
	Connected         bool
	Reconnects        uint64
	PingRTTSeconds    float64
}

// Snapshot is the full scrape-time metrics state assembled by the daemon.
type Snapshot struct {
	Peers                []PeerStat
	HandshakeRateLimited uint64
	HandshakesCompleted  uint64
	HandshakesFailed     uint64

	HasWS                 bool
	WSConnectionsActive   uint64
	WSReconnectsTotal     uint64
	WSConnectionsByResult map[string]uint64
	WSDroppedByReason     map[string]uint64
	WSRxMessages          uint64
	WSTxMessages          uint64
	WSRxBytes             uint64
	WSTxBytes             uint64
	WSPingRTTSeconds      float64
}

type Collector struct {
	snapshot func() Snapshot

	info, peers, hsRateLimited, hsTotal                           *prometheus.Desc
	wsConnActive, wsConnTotal, wsReconnects, wsDropped, wsPingRTT *prometheus.Desc
	wsRxMsgs, wsTxMsgs, wsRxBytes, wsTxBytes                      *prometheus.Desc
	peerTx, peerRx, peerLastHS, peerConnected                     *prometheus.Desc
	peerReconnects, peerPingRTT                                   *prometheus.Desc
}

func NewCollector(snapshot func() Snapshot) *Collector {
	d := func(n, h string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc(n, h, labels, nil)
	}
	return &Collector{
		snapshot:       snapshot,
		info:           d("wireguard_info", "Static build info", "version"),
		peers:          d("wireguard_peers", "Configured peers"),
		hsRateLimited:  d("wireguard_handshake_rate_limited_total", "Rate-limited handshakes"),
		hsTotal:        d("wireguard_handshakes_total", "Handshakes by result", "result"),
		wsConnActive:   d("wireguard_ws_connections_active", "Active WebSocket connections"),
		wsConnTotal:    d("wireguard_ws_connections_total", "WebSocket connections by result", "result"),
		wsReconnects:   d("wireguard_ws_reconnects_total", "WebSocket reconnects"),
		wsDropped:      d("wireguard_ws_dropped_messages_total", "Dropped WebSocket messages", "reason"),
		wsPingRTT:      d("wireguard_ws_ping_rtt_seconds", "Last WebSocket ping RTT"),
		wsRxMsgs:       d("wireguard_ws_rx_messages_total", "WebSocket rx messages"),
		wsTxMsgs:       d("wireguard_ws_tx_messages_total", "WebSocket tx messages"),
		wsRxBytes:      d("wireguard_ws_rx_bytes_total", "WebSocket rx bytes"),
		wsTxBytes:      d("wireguard_ws_tx_bytes_total", "WebSocket tx bytes"),
		peerTx:         d("wireguard_peer_tx_bytes_total", "Per-peer tx bytes", "peer"),
		peerRx:         d("wireguard_peer_rx_bytes_total", "Per-peer rx bytes", "peer"),
		peerLastHS:     d("wireguard_peer_last_handshake_timestamp_seconds", "Per-peer last handshake", "peer"),
		peerConnected:  d("wireguard_peer_connected", "Per-peer connected (1/0)", "peer"),
		peerReconnects: d("wireguard_peer_reconnects_total", "Per-peer WebSocket reconnects", "peer"),
		peerPingRTT:    d("wireguard_peer_ping_rtt_seconds", "Per-peer WebSocket ping RTT", "peer"),
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
	gv(c.info, 1, Version)
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
