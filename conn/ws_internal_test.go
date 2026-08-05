/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestWSReceiveFunc_OversizeAndClose(t *testing.T) {
	inbound := make(chan wsInbound, 1)
	done := make(chan struct{})
	fn := makeWSReceiveFunc(inbound, done)

	// Oversize: data larger than the caller buffer is dropped, not truncated.
	inbound <- wsInbound{data: make([]byte, 200), ep: &WSEndpoint{}}
	n, err := fn([][]byte{make([]byte, 100)}, make([]int, 1), make([]Endpoint, 1))
	if n != 0 || err != nil {
		t.Fatalf("oversize: n=%d err=%v, want 0,nil", n, err)
	}

	// A fitting message is delivered.
	inbound <- wsInbound{data: []byte("hello"), ep: &WSEndpoint{}}
	sizes := make([]int, 1)
	n, err = fn([][]byte{make([]byte, 100)}, sizes, make([]Endpoint, 1))
	if n != 1 || err != nil || sizes[0] != 5 {
		t.Fatalf("delivery: n=%d err=%v size=%d", n, err, sizes[0])
	}

	// After close, the receive func returns net.ErrClosed (Bind contract).
	close(done)
	if _, err := fn([][]byte{make([]byte, 100)}, make([]int, 1), make([]Endpoint, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("after close: err=%v, want net.ErrClosed", err)
	}
}

func TestWSUpgrade_Standard(t *testing.T) {
	tests := []struct {
		name      string
		bearer    string
		wantAuth  string
		wantProto bool
	}{
		{name: "no bearer", bearer: "", wantAuth: "", wantProto: false},
		{name: "with bearer", bearer: "tok123", wantAuth: "Bearer tok123", wantProto: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &WSEndpoint{url: "wss://host:443/path", dialect: wsDialectStandard, bearer: tc.bearer}
			dialURL, header, subs, err := wsUpgradeRequest(e)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if dialURL != e.url {
				t.Errorf("dialURL = %q, want %q", dialURL, e.url)
			}
			if got := header.Get("Authorization"); got != tc.wantAuth {
				t.Errorf("Authorization = %q, want %q", got, tc.wantAuth)
			}
			if (len(subs) != 0) != tc.wantProto {
				t.Errorf("subprotocols = %v", subs)
			}
		})
	}
}

func TestWSUpgrade_Wstunnel(t *testing.T) {
	e := &WSEndpoint{url: "wss://relay.example.com/myprefix", dialect: wsDialectWstunnel, target: "10.0.0.5:51820"}
	dialURL, _, subs, err := wsUpgradeRequest(e)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.HasSuffix(dialURL, "/myprefix/events") {
		t.Errorf("dialURL = %q, want .../myprefix/events", dialURL)
	}
	if len(subs) != 2 || subs[0] != "v1" || !strings.HasPrefix(subs[1], "authorization.bearer.") {
		t.Fatalf("subprotocols = %v", subs)
	}
	token := strings.TrimPrefix(subs[1], "authorization.bearer.")
	var claims wstunnelClaims
	parsed, _, err := jwt.NewParser().ParseUnverified(token, &claims)
	if err != nil {
		t.Fatalf("parse jwt: %v", err)
	}
	if parsed.Method.Alg() != "HS256" {
		t.Errorf("alg = %s, want HS256", parsed.Method.Alg())
	}
	if _, err := uuid.Parse(claims.ID); err != nil {
		t.Errorf("id %q is not a uuid: %v", claims.ID, err)
	}
	if claims.R != "10.0.0.5" || claims.RP != 51820 {
		t.Errorf("r/rp = %s/%d, want 10.0.0.5/51820", claims.R, claims.RP)
	}
	// timeout must marshal to JSON null.
	raw, _ := json.Marshal(claims.P)
	if !strings.Contains(string(raw), `"timeout":null`) {
		t.Errorf("p = %s, want timeout:null", raw)
	}
}

func TestWSUpgrade_WstunnelDefaultPrefix(t *testing.T) {
	// A wstunnel endpoint with no path must target wstunnel's default /v1/events
	// (DEFAULT_CLIENT_UPGRADE_PATH_PREFIX = "v1"), matching the stock wstunnel client.
	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "no path", url: "wss://relay.example.com:8443", want: "/v1/events"},
		{name: "root path", url: "wss://relay.example.com:8443/", want: "/v1/events"},
		{name: "explicit prefix preserved", url: "wss://relay.example.com/custom", want: "/custom/events"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &WSEndpoint{url: tc.url, dialect: wsDialectWstunnel, target: "10.0.0.5:51820"}
			dialURL, _, _, err := wsUpgradeRequest(e)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if !strings.HasSuffix(dialURL, tc.want) {
				t.Errorf("dialURL = %q, want suffix %q", dialURL, tc.want)
			}
		})
	}
}

func TestWstunnelJWT_Verifiable(t *testing.T) {
	secret := []byte("shared-test-secret")
	tok, err := wstunnelJWT("host:1234", secret)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	_, err = jwt.Parse(tok, func(*jwt.Token) (any, error) { return secret, nil })
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// A bad target errors.
	if _, err := wstunnelJWT("noport", secret); err == nil {
		t.Error("expected error for target without port")
	}
}

func TestResolveClientAddr(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	tests := []struct {
		name    string
		remote  string
		xff     string
		trusted []netip.Prefix
		want    string
	}{
		{name: "untrusted peer ignores xff", remote: "203.0.113.9:5000", xff: "1.2.3.4", trusted: trusted, want: "203.0.113.9"},
		{name: "trusted peer honors xff", remote: "10.0.0.1:5000", xff: "203.0.113.9", trusted: trusted, want: "203.0.113.9"},
		{name: "multi-hop strips trusted", remote: "10.0.0.1:5000", xff: "203.0.113.9, 10.0.0.2", trusted: trusted, want: "203.0.113.9"},
		{name: "empty config raw peer", remote: "10.0.0.1:5000", xff: "203.0.113.9", trusted: nil, want: "10.0.0.1"},
		{name: "trusted peer no xff", remote: "10.0.0.1:5000", xff: "", trusted: trusted, want: "10.0.0.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remote
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			got := resolveClientAddr(r, tc.trusted)
			if got.Addr().String() != tc.want {
				t.Errorf("addr = %s, want %s", got.Addr(), tc.want)
			}
		})
	}
}

func TestWSDebounce(t *testing.T) {
	var n int
	var mu sync.Mutex
	d := newWSDebounce(30*time.Millisecond, func() {
		mu.Lock()
		n++
		mu.Unlock()
	})
	for i := 0; i < 5; i++ {
		d.trigger()
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	got := n
	mu.Unlock()
	if got != 1 {
		t.Errorf("onChange fired %d times, want 1 (coalesced)", got)
	}
	d.stop()
}

func TestWSPathMonitor_StartClose(t *testing.T) {
	m := NewWSPathMonitor(Logger{})
	if m == nil {
		t.Fatal("nil monitor")
	}
	if err := m.Start(func() {}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Give any initial update handler a moment, then shut down cleanly.
	time.Sleep(50 * time.Millisecond)
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close is idempotent.
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestWSMetricsState(t *testing.T) {
	b := &WebSocketBind{}
	b.metrics.incConn(1, "ok")
	b.metrics.incConn(1, "ok")
	b.metrics.incConn(-1, "")
	b.metrics.incReconnect("wss://a/x")
	b.metrics.observeRTT("wss://a/x", 0.5)
	b.metrics.addRx(2, 100)
	b.metrics.addTx(3, 200)
	b.metrics.drop("queue_full")

	snap := b.WSMetricsSnapshot()
	if snap.ConnectionsActive != 1 {
		t.Errorf("active = %d, want 1", snap.ConnectionsActive)
	}
	if snap.ConnectionsByResult["ok"] != 2 {
		t.Errorf("ok = %d, want 2", snap.ConnectionsByResult["ok"])
	}
	if snap.ReconnectsTotal != 1 || snap.PerEndpoint["wss://a/x"].Reconnects != 1 {
		t.Errorf("reconnects wrong: %+v", snap)
	}
	if snap.PerEndpoint["wss://a/x"].PingRTTSeconds != 0.5 || snap.LastPingRTTSeconds != 0.5 {
		t.Errorf("rtt wrong: %+v", snap)
	}
	if snap.RxMessages != 2 || snap.TxBytes != 200 || snap.DroppedByReason["queue_full"] != 1 {
		t.Errorf("counters wrong: %+v", snap)
	}
}
