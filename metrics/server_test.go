/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package metrics_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"golang.zx2c4.com/wireguard/metrics"
)

func TestMetricsServer_Serves(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewCollector(func() metrics.Snapshot {
		return metrics.Snapshot{HandshakesCompleted: 1}
	}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- metrics.Serve(ctx, addr, reg) }()

	var body string
	ok := false
	for i := 0; i < 50; i++ {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(b)
			ok = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ok {
		t.Fatal("metrics endpoint never came up")
	}
	if !strings.Contains(body, "wireguard_handshakes_total") {
		t.Errorf("unexpected body:\n%s", body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned error: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Error("Serve did not shut down on context cancel")
	}
}
