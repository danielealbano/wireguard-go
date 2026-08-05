/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

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
	rxMessages          uint64
	txMessages          uint64
	rxBytes             uint64
	txBytes             uint64
	droppedByReason     map[string]uint64 // e.g. "queue_full"
	lastPingRTTSeconds  float64           // most recent RTT across all conns (high-level metric)
	perEndpoint         map[string]*wsEndpointMetric
}

// WSMetrics is a scrape-time snapshot of the WebSocket bind counters.
type WSMetrics struct {
	ConnectionsActive   uint64
	ConnectionsByResult map[string]uint64
	ReconnectsTotal     uint64
	RxMessages          uint64
	TxMessages          uint64
	RxBytes             uint64
	TxBytes             uint64
	DroppedByReason     map[string]uint64
	LastPingRTTSeconds  float64
	PerEndpoint         map[string]WSEndpointMetric // key = DstToString
}

type WSEndpointMetric struct {
	Reconnects     uint64
	PingRTTSeconds float64
}

// WebSocketMetricsProvider is the optional interface the daemon type-asserts to
// collect WebSocket-bind metrics. The metrics package does not import conn.
type WebSocketMetricsProvider interface {
	WSMetricsSnapshot() WSMetrics
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
	} else if delta < 0 && s.connectionsActive > 0 {
		s.connectionsActive--
	} else if delta == 0 && result != "" {
		s.connectionsByResult[result]++
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

func (s *wsMetricsState) addRx(msgs, bytes uint64) {
	s.mu.Lock()
	s.rxMessages += msgs
	s.rxBytes += bytes
	s.mu.Unlock()
}

func (s *wsMetricsState) addTx(msgs, bytes uint64) {
	s.mu.Lock()
	s.txMessages += msgs
	s.txBytes += bytes
	s.mu.Unlock()
}

func (s *wsMetricsState) drop(reason string) {
	s.mu.Lock()
	s.ensure()
	s.droppedByReason[reason]++
	s.mu.Unlock()
}

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
