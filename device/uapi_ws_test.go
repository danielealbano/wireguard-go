/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

type wsCall struct{ url, mode, target, bearer string }

// mockWSBind implements conn.Bind + conn.WebSocketBinder, recording the peer
// endpoint parse calls so tests can assert per-peer WS key isolation.
type mockWSBind struct {
	mu    sync.Mutex
	calls []wsCall
}

func (m *mockWSBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, 0, nil }
func (m *mockWSBind) Close() error                                    { return nil }
func (m *mockWSBind) SetMark(uint32) error                            { return nil }
func (m *mockWSBind) Send([][]byte, conn.Endpoint) error              { return nil }
func (m *mockWSBind) BatchSize() int                                  { return 1 }
func (m *mockWSBind) SetWSListen(string) error                        { return nil }

func (m *mockWSBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return m.ParseWSPeerEndpoint(s, "standard", "", "")
}

func (m *mockWSBind) ParseWSPeerEndpoint(url, mode, target, bearer string) (conn.Endpoint, error) {
	m.mu.Lock()
	m.calls = append(m.calls, wsCall{url, mode, target, bearer})
	m.mu.Unlock()
	return mockWSEndpoint(url), nil
}

type mockWSEndpoint string

func (e mockWSEndpoint) ClearSrc()           {}
func (e mockWSEndpoint) SrcToString() string { return "" }
func (e mockWSEndpoint) DstToString() string { return string(e) }
func (e mockWSEndpoint) DstToBytes() []byte  { return nil }
func (e mockWSEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e mockWSEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func randKeyHex(t *testing.T) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(k[:])
}

func newWSTestDevice(t *testing.T, bind conn.Bind, logger *Logger) *Device {
	t.Helper()
	tun := tuntest.NewChannelTUN()
	if logger == nil {
		logger = NewLogger(LogLevelError, "")
	}
	dev := NewDevice(tun.TUN(), bind, logger)
	t.Cleanup(dev.Close)
	return dev
}

func TestUAPI_WSKeys_Accepted(t *testing.T) {
	dev := newWSTestDevice(t, &mockWSBind{}, nil)
	cfg := "private_key=" + randKeyHex(t) + "\n" +
		"public_key=" + randKeyHex(t) + "\n" +
		"endpoint=wss://server.example.com/wg\n" +
		"ws_mode=wstunnel\n" +
		"ws_target=10.0.0.9:51820\n" +
		"ws_bearer=coarse-gate\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet with WS keys: %v", err)
	}
	// A genuinely unknown key is still rejected.
	if err := dev.IpcSet("public_key=" + randKeyHex(t) + "\nnot_a_real_key=1\n"); err == nil {
		t.Error("expected error for unknown peer key")
	}
}

func TestUAPI_WSListen_RequiresWSBind(t *testing.T) {
	dev := newWSTestDevice(t, conn.NewDefaultBind(), nil)
	err := dev.IpcSet("ws_listen=ws://127.0.0.1:9999/wg\n")
	if err == nil {
		t.Fatal("ws_listen on a UDP bind must be rejected")
	}
}

func TestUAPI_Bearer_EchoedForRoundTrip(t *testing.T) {
	// ws_bearer is echoed by IpcGet (like private_key/preshared_key, over the same trusted
	// socket) so a bearer-authed peer survives a get -> set reload. It must still never be
	// logged (see TestUAPI_Bearer_NotLogged).
	dev := newRealWSClientDevice(t)
	const bearer = "super-secret-token"
	cfg := "private_key=" + randKeyHex(t) + "\n" +
		"public_key=" + randKeyHex(t) + "\n" +
		"endpoint=wss://server.example.com/wg\n" +
		"ws_bearer=" + bearer + "\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if !strings.Contains(got, "ws_bearer="+bearer) {
		t.Errorf("IpcGet did not round-trip the bearer:\n%s", got)
	}
}

func TestUAPI_Bearer_NotLogged(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	writef := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&buf, format, args...)
	}
	logger := &Logger{Verbosef: writef, Errorf: writef}
	dev := newWSTestDevice(t, &mockWSBind{}, logger)
	cfg := "private_key=" + randKeyHex(t) + "\n" +
		"public_key=" + randKeyHex(t) + "\n" +
		"endpoint=wss://server.example.com/wg\n" +
		"ws_bearer=do-not-log-me\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	mu.Lock()
	logged := buf.String()
	mu.Unlock()
	if strings.Contains(logged, "do-not-log-me") {
		t.Errorf("bearer value leaked into logs:\n%s", logged)
	}
}

func TestUAPI_WSKeys_NotLeakedAcrossPeers(t *testing.T) {
	bind := &mockWSBind{}
	dev := newWSTestDevice(t, bind, nil)
	cfg := "private_key=" + randKeyHex(t) + "\n" +
		"public_key=" + randKeyHex(t) + "\n" +
		"endpoint=ws://h/1\n" +
		"ws_mode=wstunnel\n" +
		"ws_target=1.2.3.4:5\n" +
		"ws_bearer=peer1-secret\n" +
		"public_key=" + randKeyHex(t) + "\n" +
		"endpoint=ws://h/2\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if len(bind.calls) != 2 {
		t.Fatalf("got %d parse calls, want 2: %+v", len(bind.calls), bind.calls)
	}
	p2 := bind.calls[1]
	if p2.mode != "" || p2.target != "" || p2.bearer != "" {
		t.Errorf("peer 2 inherited WS keys from peer 1: %+v", p2)
	}
}

// newRealWSClientDevice builds a device on a real client-role WebSocket bind, so peer
// endpoints are genuine conn.WSEndpoints (which IpcGet round-trips) rather than mocks.
func newRealWSClientDevice(t *testing.T) *Device {
	t.Helper()
	b, err := conn.NewWebSocketBind(conn.WithWSRole(conn.WSRoleClient))
	if err != nil {
		t.Fatalf("client bind: %v", err)
	}
	return newWSTestDevice(t, b, nil)
}

func TestUAPI_Get_EmitsWSPeerKeys(t *testing.T) {
	tests := []struct {
		name       string
		peerCfg    string
		wantLines  []string
		absentKeys []string
	}{
		{
			name:       "standard mode omits target and bearer",
			peerCfg:    "endpoint=wss://server.example.com/wg\n",
			wantLines:  []string{"endpoint=wss://server.example.com/wg", "ws_mode=standard"},
			absentKeys: []string{"ws_target=", "ws_bearer="},
		},
		{
			name: "wstunnel mode with target and bearer",
			peerCfg: "endpoint=wss://relay.example.com:8443\n" +
				"ws_mode=wstunnel\nws_target=10.0.0.9:51820\nws_bearer=tok\n",
			wantLines: []string{
				"endpoint=wss://relay.example.com:8443",
				"ws_mode=wstunnel",
				"ws_target=10.0.0.9:51820",
				"ws_bearer=tok",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dev := newRealWSClientDevice(t)
			cfg := "private_key=" + randKeyHex(t) + "\npublic_key=" + randKeyHex(t) + "\n" + tc.peerCfg
			if err := dev.IpcSet(cfg); err != nil {
				t.Fatalf("IpcSet: %v", err)
			}
			got, err := dev.IpcGet()
			if err != nil {
				t.Fatalf("IpcGet: %v", err)
			}
			for _, line := range tc.wantLines {
				if !strings.Contains(got, line) {
					t.Errorf("IpcGet missing %q:\n%s", line, got)
				}
			}
			for _, k := range tc.absentKeys {
				if strings.Contains(got, k) {
					t.Errorf("IpcGet unexpectedly contains %q:\n%s", k, got)
				}
			}
		})
	}
}

func TestUAPI_Get_EmitsWSListen(t *testing.T) {
	const listenURL = "wss://0.0.0.0:443/wg"
	b, err := conn.NewWebSocketBind(conn.WithWSRole(conn.WSRoleServer), conn.WithWSListenURL(listenURL))
	if err != nil {
		t.Fatalf("server bind: %v", err)
	}
	dev := newWSTestDevice(t, b, nil)
	if err := dev.IpcSet("private_key=" + randKeyHex(t) + "\n"); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if !strings.Contains(got, "ws_listen="+listenURL) {
		t.Errorf("IpcGet missing ws_listen:\n%s", got)
	}
}

func TestUAPI_Get_UDPTransportHasNoWSKeys(t *testing.T) {
	dev := newWSTestDevice(t, conn.NewDefaultBind(), nil)
	cfg := "private_key=" + randKeyHex(t) + "\nlisten_port=0\n" +
		"public_key=" + randKeyHex(t) + "\nendpoint=127.0.0.1:51820\nallowed_ip=1.0.0.0/24\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if strings.Contains(got, "ws_") {
		t.Errorf("UDP transport IpcGet contains ws_ keys:\n%s", got)
	}
}

// TestUAPI_Get_WSKeys_RoundTrip proves the additive WS keys survive a get -> set -> get
// cycle: feeding IpcGet's output back into a fresh device (keeping only set-valid keys)
// reconstructs the same endpoint and ws_* lines.
func TestUAPI_Get_WSKeys_RoundTrip(t *testing.T) {
	dev1 := newRealWSClientDevice(t)
	cfg := "private_key=" + randKeyHex(t) + "\npublic_key=" + randKeyHex(t) + "\n" +
		"endpoint=wss://relay.example.com:8443\n" +
		"ws_mode=wstunnel\nws_target=10.0.0.9:51820\nws_bearer=tok\n" +
		"allowed_ip=1.0.0.0/24\n"
	if err := dev1.IpcSet(cfg); err != nil {
		t.Fatalf("dev1 IpcSet: %v", err)
	}
	g1, err := dev1.IpcGet()
	if err != nil {
		t.Fatalf("dev1 IpcGet: %v", err)
	}

	// Keep only keys the set operation accepts (drops get-only fields like tx_bytes).
	allow := map[string]bool{
		"private_key": true, "public_key": true, "endpoint": true,
		"ws_mode": true, "ws_target": true, "ws_bearer": true,
		"allowed_ip": true, "persistent_keepalive_interval": true,
	}
	var sb strings.Builder
	for _, line := range strings.Split(g1, "\n") {
		if k, _, ok := strings.Cut(line, "="); ok && allow[k] {
			sb.WriteString(line)
			sb.WriteByte('\n')
		}
	}
	dev2 := newRealWSClientDevice(t)
	if err := dev2.IpcSet(sb.String()); err != nil {
		t.Fatalf("dev2 IpcSet (from get output): %v\ninput:\n%s", err, sb.String())
	}
	g2, err := dev2.IpcGet()
	if err != nil {
		t.Fatalf("dev2 IpcGet: %v", err)
	}

	wsLines := func(s string) []string {
		var out []string
		for _, l := range strings.Split(s, "\n") {
			if strings.HasPrefix(l, "ws_") || strings.HasPrefix(l, "endpoint=") {
				out = append(out, l)
			}
		}
		sort.Strings(out)
		return out
	}
	got1, got2 := wsLines(g1), wsLines(g2)
	if len(got1) == 0 {
		t.Fatalf("dev1 emitted no WS keys to round-trip:\n%s", g1)
	}
	if !reflect.DeepEqual(got1, got2) {
		t.Errorf("WS keys not preserved across get -> set -> get:\ndev1: %v\ndev2: %v", got1, got2)
	}
}
