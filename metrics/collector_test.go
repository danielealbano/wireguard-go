/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package metrics_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"golang.zx2c4.com/wireguard/metrics"
)

func scrape(t *testing.T, snap metrics.Snapshot) string {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewCollector(func() metrics.Snapshot { return snap }))
	h := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("scrape status %d", rec.Code)
	}
	return rec.Body.String()
}

func fullSnapshot() metrics.Snapshot {
	return metrics.Snapshot{
		Peers: []metrics.PeerStat{{
			PublicKey: [32]byte{1, 2, 3}, Endpoint: "wss://a/x",
			TxBytes: 10, RxBytes: 20, Connected: true, Reconnects: 4, PingRTTSeconds: 0.25,
		}},
		HandshakeRateLimited:  1,
		HandshakesCompleted:   3,
		HandshakesFailed:      2,
		HasWS:                 true,
		WSConnectionsActive:   1,
		WSConnectionsByResult: map[string]uint64{"ok": 5},
		WSReconnectsTotal:     4,
		WSDroppedByReason:     map[string]uint64{"queue_full": 7},
		WSRxMessages:          11,
		WSTxMessages:          12,
		WSRxBytes:             100,
		WSTxBytes:             200,
		WSPingRTTSeconds:      0.25,
	}
}

func TestCollector_Output(t *testing.T) {
	body := scrape(t, fullSnapshot())
	for _, want := range []string{
		"wireguard_peers 1",
		"wireguard_handshake_rate_limited_total 1",
		`wireguard_handshakes_total{result="completed"} 3`,
		`wireguard_handshakes_total{result="failed"} 2`,
		"wireguard_ws_connections_active 1",
		`wireguard_ws_connections_total{result="ok"} 5`,
		"wireguard_ws_reconnects_total 4",
		`wireguard_ws_dropped_messages_total{reason="queue_full"} 7`,
		"wireguard_peer_tx_bytes_total{peer=",
		"wireguard_peer_reconnects_total{peer=",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\n%s", want, body)
		}
	}
}

func TestCollector_NoWS(t *testing.T) {
	snap := metrics.Snapshot{
		Peers:               []metrics.PeerStat{{PublicKey: [32]byte{9}, TxBytes: 1}},
		HandshakesCompleted: 1,
		HasWS:               false,
	}
	body := scrape(t, snap)
	if strings.Contains(body, "wireguard_ws_connections_active") {
		t.Errorf("UDP transport must not emit WS metrics:\n%s", body)
	}
	if !strings.Contains(body, "wireguard_peer_tx_bytes_total{peer=") {
		t.Errorf("device/peer metrics missing:\n%s", body)
	}
}

func TestCollector_PerPeerJoin(t *testing.T) {
	body := scrape(t, fullSnapshot())
	// The per-peer reconnect/rtt values come from the joined per-endpoint WS stats.
	if !strings.Contains(body, "} 4") { // wireguard_peer_reconnects_total{peer="..."} 4
		t.Errorf("per-peer reconnects (4) not joined:\n%s", body)
	}
	if !strings.Contains(body, "wireguard_peer_ping_rtt_seconds{peer=") {
		t.Errorf("per-peer ping rtt missing:\n%s", body)
	}
}
