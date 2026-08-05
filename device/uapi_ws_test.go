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

func TestUAPI_Bearer_NotEchoed(t *testing.T) {
	dev := newWSTestDevice(t, &mockWSBind{}, nil)
	cfg := "private_key=" + randKeyHex(t) + "\n" +
		"public_key=" + randKeyHex(t) + "\n" +
		"endpoint=wss://server.example.com/wg\n" +
		"ws_bearer=super-secret-token\n"
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if strings.Contains(got, "ws_bearer") || strings.Contains(got, "super-secret-token") {
		t.Errorf("IpcGet leaked the bearer:\n%s", got)
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
