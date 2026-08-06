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

// mockWSBind implements conn.Bind + conn.WebSocketBinder + the get reporters,
// recording the per-peer endpoint-build calls and device-level server settings so
// tests can assert key isolation, validation, and round-tripping.
type mockWSBind struct {
	mu             sync.Mutex
	calls          []conn.WSPeerConfig
	listen         string
	serverCert     string
	serverKey      string
	serverBearer   string
	trustedProxies []netip.Prefix
}

func (m *mockWSBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, 0, nil }
func (m *mockWSBind) Close() error                                    { return nil }
func (m *mockWSBind) SetMark(uint32) error                            { return nil }
func (m *mockWSBind) Send([][]byte, conn.Endpoint) error              { return nil }
func (m *mockWSBind) BatchSize() int                                  { return 1 }

func (m *mockWSBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return mockUDPEndpoint(ap.String()), nil
}

func (m *mockWSBind) ParseWSPeerEndpoint(cfg conn.WSPeerConfig) (conn.Endpoint, error) {
	m.mu.Lock()
	m.calls = append(m.calls, cfg)
	m.mu.Unlock()
	return mockUDPEndpoint(cfg.Endpoint.String()), nil
}

func (m *mockWSBind) SetWSListen(u string) error         { m.mu.Lock(); m.listen = u; m.mu.Unlock(); return nil }
func (m *mockWSBind) SetServerCertPath(p string)         { m.mu.Lock(); m.serverCert = p; m.mu.Unlock() }
func (m *mockWSBind) SetServerKeyPath(p string)          { m.mu.Lock(); m.serverKey = p; m.mu.Unlock() }
func (m *mockWSBind) SetServerBearer(b string)           { m.mu.Lock(); m.serverBearer = b; m.mu.Unlock() }
func (m *mockWSBind) SetTrustedProxies(p []netip.Prefix) { m.mu.Lock(); m.trustedProxies = p; m.mu.Unlock() }

func (m *mockWSBind) WSListenURL() string                { m.mu.Lock(); defer m.mu.Unlock(); return m.listen }
func (m *mockWSBind) WSServerBearer() string             { m.mu.Lock(); defer m.mu.Unlock(); return m.serverBearer }
func (m *mockWSBind) WSTrustedProxies() []netip.Prefix   { m.mu.Lock(); defer m.mu.Unlock(); return m.trustedProxies }
func (m *mockWSBind) WSServerTLSPaths() (string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.serverCert, m.serverKey
}

type mockUDPEndpoint string

func (e mockUDPEndpoint) ClearSrc()           {}
func (e mockUDPEndpoint) SrcToString() string { return "" }
func (e mockUDPEndpoint) DstToString() string { return string(e) }
func (e mockUDPEndpoint) DstToBytes() []byte  { return nil }
func (e mockUDPEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (e mockUDPEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

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

// newRealMultiplexDevice builds a device on a real multiplexing bind, so peer
// endpoints are genuine (UDP StdNetEndpoints / conn.WSEndpoints) that IpcGet
// round-trips, and all three transports can coexist on one device.
func newRealMultiplexDevice(t *testing.T) *Device {
	t.Helper()
	b, err := conn.NewMultiplexBind(conn.WithWSLogger(conn.Logger{}))
	if err != nil {
		t.Fatalf("multiplex bind: %v", err)
	}
	return newWSTestDevice(t, b, nil)
}

func TestUAPI_Set_TransportMandatoryAtCreation(t *testing.T) {
	dev := newWSTestDevice(t, &mockWSBind{}, nil)
	// Creating a peer with no transport line is rejected.
	if err := dev.IpcSet("private_key=" + randKeyHex(t) + "\npublic_key=" + randKeyHex(t) + "\nallowed_ip=1.0.0.2/32\n"); err == nil {
		t.Error("peer created without transport= should be rejected")
	}
	// An invalid transport is rejected.
	if err := dev.IpcSet("public_key=" + randKeyHex(t) + "\ntransport=carrier-pigeon\n"); err == nil {
		t.Error("invalid transport should be rejected")
	}
	// Each valid transport is accepted (websocket/wstunnel need ws_url+endpoint to dial;
	// here they are inbound peers with no ws_url).
	for _, tr := range []string{"udp", "websocket", "wstunnel"} {
		if err := dev.IpcSet("public_key=" + randKeyHex(t) + "\ntransport=" + tr + "\nallowed_ip=1.0.0.2/32\n"); err != nil {
			t.Errorf("transport=%s rejected: %v", tr, err)
		}
	}
}

func TestUAPI_Set_IncrementalUpdateKeepsTransport(t *testing.T) {
	dev := newRealMultiplexDevice(t)
	pub := randKeyHex(t)
	if err := dev.IpcSet("private_key=" + randKeyHex(t) + "\npublic_key=" + pub + "\ntransport=websocket\nendpoint=203.0.113.5:8443\nws_url=wss://relay:8443/wg\nallowed_ip=1.0.0.2/32\n"); err != nil {
		t.Fatalf("create: %v", err)
	}
	// allowed_ip-only update, no transport: must be accepted.
	if err := dev.IpcSet("public_key=" + pub + "\nallowed_ip=1.0.0.3/32\n"); err != nil {
		t.Errorf("incremental update (allowed_ip) rejected: %v", err)
	}
	// Re-send ws_url+endpoint without transport: rebuilds via the persisted transport.
	if err := dev.IpcSet("public_key=" + pub + "\nendpoint=203.0.113.9:8443\nws_url=wss://relay:8443/wg\n"); err != nil {
		t.Errorf("incremental update (ws_url) rejected: %v", err)
	}
}

func TestUAPI_Set_EndpointIsPlainIPPort(t *testing.T) {
	bind := &mockWSBind{}
	dev := newWSTestDevice(t, bind, nil)
	if err := dev.IpcSet("private_key=" + randKeyHex(t) + "\npublic_key=" + randKeyHex(t) + "\ntransport=websocket\nendpoint=203.0.113.5:8443\nws_url=wss://relay:8443/wg\n"); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if len(bind.calls) != 1 {
		t.Fatalf("got %d build calls, want 1", len(bind.calls))
	}
	if bind.calls[0].Endpoint != netip.MustParseAddrPort("203.0.113.5:8443") {
		t.Errorf("built with endpoint %v, want 203.0.113.5:8443", bind.calls[0].Endpoint)
	}
	if bind.calls[0].URL != "wss://relay:8443/wg" {
		t.Errorf("built with url %q", bind.calls[0].URL)
	}
}

func TestUAPI_Set_InboundWSPeer_NoURL(t *testing.T) {
	bind := &mockWSBind{}
	dev := newWSTestDevice(t, bind, nil)
	if err := dev.IpcSet("private_key=" + randKeyHex(t) + "\npublic_key=" + randKeyHex(t) + "\ntransport=websocket\nallowed_ip=1.0.0.2/32\n"); err != nil {
		t.Fatalf("inbound WS peer (no ws_url) rejected: %v", err)
	}
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if len(bind.calls) != 0 {
		t.Errorf("inbound peer should build no dial endpoint, got %d calls", len(bind.calls))
	}
}

func TestUAPI_Set_Validation(t *testing.T) {
	tests := []struct {
		name string
		peer string
	}{
		{"ws_* rejected for udp", "transport=udp\nendpoint=203.0.113.5:8443\nws_url=wss://relay:8443\n"},
		{"ws_mask rejected for udp", "transport=udp\nendpoint=203.0.113.5:8443\nws_mask=true\n"},
		{"dialing websocket requires endpoint", "transport=websocket\nws_url=wss://relay:8443\n"},
		{"wstunnel_target requires ws_url", "transport=websocket\nallowed_ip=1.0.0.2/32\nwstunnel_target=10.0.0.9:51820\n"},
		{"wstunnel_target on websocket transport", "transport=websocket\nendpoint=203.0.113.5:8443\nws_url=wss://relay:8443\nwstunnel_target=10.0.0.9:51820\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dev := newWSTestDevice(t, &mockWSBind{}, nil)
			cfg := "private_key=" + randKeyHex(t) + "\npublic_key=" + randKeyHex(t) + "\n" + tc.peer
			if err := dev.IpcSet(cfg); err == nil {
				t.Errorf("expected rejection, got nil")
			}
		})
	}
}

func TestUAPI_WSKeys_NotLeakedAcrossPeers(t *testing.T) {
	bind := &mockWSBind{}
	dev := newWSTestDevice(t, bind, nil)
	cfg := "private_key=" + randKeyHex(t) + "\n" +
		"public_key=" + randKeyHex(t) + "\ntransport=wstunnel\nendpoint=203.0.113.5:8443\nws_url=wss://h/1\nwstunnel_target=1.2.3.4:5\nws_bearer=peer1-secret\n" +
		"public_key=" + randKeyHex(t) + "\ntransport=websocket\nendpoint=203.0.113.6:8443\nws_url=wss://h/2\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if len(bind.calls) != 2 {
		t.Fatalf("got %d build calls, want 2: %+v", len(bind.calls), bind.calls)
	}
	if p2 := bind.calls[1]; p2.WstunnelTarget != "" || p2.Bearer != "" {
		t.Errorf("peer 2 inherited WS keys from peer 1: %+v", p2)
	}
}

func TestUAPI_WSListen_RequiresWSBind(t *testing.T) {
	dev := newWSTestDevice(t, conn.NewDefaultBind(), nil)
	if err := dev.IpcSet("ws_listen=ws://127.0.0.1:9999/wg\n"); err == nil {
		t.Fatal("ws_listen on a UDP bind must be rejected")
	}
	if err := dev.IpcSet("ws_server_bearer=x\n"); err == nil {
		t.Fatal("ws_server_bearer on a UDP bind must be rejected")
	}
}

func TestUAPI_Get_RoundTrip_AllTransports(t *testing.T) {
	dev1 := newRealMultiplexDevice(t)
	udpPub, wsPub, wstPub, inPub := randKeyHex(t), randKeyHex(t), randKeyHex(t), randKeyHex(t)
	cfg := "private_key=" + randKeyHex(t) + "\nlisten_port=0\n" +
		"ws_listen=wss://0.0.0.0:8443/wg\nws_server_bearer=srv-secret\nws_trusted_proxies=10.0.0.0/8\n" +
		"public_key=" + udpPub + "\ntransport=udp\nendpoint=198.51.100.1:51820\nallowed_ip=1.0.0.1/32\n" +
		"public_key=" + wsPub + "\ntransport=websocket\nendpoint=203.0.113.5:8443\nws_url=wss://relay.example.com:8443/wg\nws_mask=true\nallowed_ip=1.0.0.2/32\n" +
		"public_key=" + wstPub + "\ntransport=wstunnel\nendpoint=203.0.113.6:8443\nws_url=wss://relay.example.com:8443\nwstunnel_target=10.0.0.9:51820\nws_bearer=tok\nallowed_ip=1.0.0.3/32\n" +
		"public_key=" + inPub + "\ntransport=websocket\nallowed_ip=1.0.0.4/32\n"
	if err := dev1.IpcSet(cfg); err != nil {
		t.Fatalf("dev1 IpcSet: %v", err)
	}
	g1, err := dev1.IpcGet()
	if err != nil {
		t.Fatalf("dev1 IpcGet: %v", err)
	}
	// Every peer must carry a transport= line (4 peers).
	if n := strings.Count(g1, "transport="); n != 4 {
		t.Errorf("got %d transport= lines, want 4:\n%s", n, g1)
	}

	// Feed the get output back (keeping only set-valid keys) into a fresh device.
	allow := map[string]bool{
		"private_key": true, "listen_port": true, "public_key": true, "transport": true,
		"endpoint": true, "ws_url": true, "wstunnel_target": true, "ws_bearer": true,
		"ws_mask": true, "ws_tls_ca": true, "ws_tls_cert": true, "ws_tls_key": true,
		"ws_tls_insecure": true, "ws_ping_interval": true, "ws_backoff_min": true,
		"ws_backoff_max": true, "allowed_ip": true, "persistent_keepalive_interval": true,
		"ws_listen": true, "ws_server_bearer": true, "ws_trusted_proxies": true,
		"ws_server_tls_cert": true, "ws_server_tls_key": true,
	}
	var sb strings.Builder
	for _, line := range strings.Split(g1, "\n") {
		if k, _, ok := strings.Cut(line, "="); ok && allow[k] {
			sb.WriteString(line)
			sb.WriteByte('\n')
		}
	}
	dev2 := newRealMultiplexDevice(t)
	if err := dev2.IpcSet(sb.String()); err != nil {
		t.Fatalf("dev2 IpcSet (from get output): %v\ninput:\n%s", err, sb.String())
	}
	g2, err := dev2.IpcGet()
	if err != nil {
		t.Fatalf("dev2 IpcGet: %v", err)
	}
	if a, b := transportAndWSLines(g1), transportAndWSLines(g2); !reflect.DeepEqual(a, b) {
		t.Errorf("transport/WS keys not preserved across get->set->get:\ndev1: %v\ndev2: %v", a, b)
	}
}

// transportAndWSLines extracts the transport/ws_*/endpoint/wstunnel_target lines,
// sorted, for a stable round-trip comparison.
func transportAndWSLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "transport=") || strings.HasPrefix(l, "ws_") ||
			strings.HasPrefix(l, "wstunnel_target=") || strings.HasPrefix(l, "endpoint=") {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

func TestUAPI_Get_UDPPeerHasNoWSKeys(t *testing.T) {
	dev := newRealMultiplexDevice(t)
	cfg := "private_key=" + randKeyHex(t) + "\nlisten_port=0\n" +
		"public_key=" + randKeyHex(t) + "\ntransport=udp\nendpoint=127.0.0.1:51820\nallowed_ip=1.0.0.0/24\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if !strings.Contains(got, "transport=udp") {
		t.Errorf("UDP peer missing transport=udp:\n%s", got)
	}
	if strings.Contains(got, "ws_url") || strings.Contains(got, "wstunnel_target") {
		t.Errorf("UDP peer emitted WS keys:\n%s", got)
	}
}

func TestUAPI_Get_NeverLogsSecrets(t *testing.T) {
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
		"ws_listen=ws://127.0.0.1:0/wg\nws_server_bearer=server-secret\n" +
		"public_key=" + randKeyHex(t) + "\ntransport=websocket\nendpoint=203.0.113.5:8443\nws_url=wss://relay:8443/wg\nws_bearer=peer-secret\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	if _, err := dev.IpcGet(); err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	mu.Lock()
	logged := buf.String()
	mu.Unlock()
	for _, secret := range []string{"peer-secret", "server-secret"} {
		if strings.Contains(logged, secret) {
			t.Errorf("secret %q leaked into logs:\n%s", secret, logged)
		}
	}
}

func TestUAPI_ServerKeys_RoundTrip(t *testing.T) {
	bind := &mockWSBind{}
	dev := newWSTestDevice(t, bind, nil)
	cfg := "private_key=" + randKeyHex(t) + "\n" +
		"ws_listen=ws://0.0.0.0:8443/wg\nws_server_tls_cert=/etc/wg/cert.pem\nws_server_tls_key=/etc/wg/key.pem\nws_server_bearer=srv\nws_trusted_proxies=10.0.0.0/8\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	for _, want := range []string{
		"ws_listen=ws://0.0.0.0:8443/wg", "ws_server_tls_cert=/etc/wg/cert.pem",
		"ws_server_tls_key=/etc/wg/key.pem", "ws_server_bearer=srv", "ws_trusted_proxies=10.0.0.0/8",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("IpcGet missing %q:\n%s", want, got)
		}
	}
}
