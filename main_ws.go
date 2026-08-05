/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/metrics"
)

// buildWSOptionsFromEnv assembles the process-level WebSocket configuration from
// the WG_WS_* environment. Secrets (WG_WS_BEARER, TLS material) are never logged.
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

	ca, sni := os.Getenv("WG_WS_TLS_CA"), os.Getenv("WG_WS_TLS_SERVERNAME")
	insecure := os.Getenv("WG_WS_TLS_INSECURE") == "1"
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
