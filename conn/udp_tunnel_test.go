/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// newUDPDevicePair brings up two WireGuard devices on real loopback UDP binds
// (conn.NewDefaultBind), cross-configured so they tunnel over UDP — the UDP analogue
// of newWSDevicePair. Each bind's actual port is read back from IpcGet after Up, so
// the peers can point at each other.
func newUDPDevicePair(t *testing.T) (a, b *tuntest.ChannelTUN) {
	t.Helper()
	priv1, pub1 := wgKeypair(t)
	priv2, pub2 := wgKeypair(t)

	mk := func(selfPriv string) (*tuntest.ChannelTUN, *device.Device) {
		tdev := tuntest.NewChannelTUN()
		d := device.NewDevice(tdev.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
		if err := d.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\n", selfPriv)); err != nil {
			t.Fatalf("IpcSet: %v", err)
		}
		if err := d.Up(); err != nil {
			t.Fatalf("Up: %v", err)
		}
		t.Cleanup(d.Close)
		return tdev, d
	}
	ta, da := mk(priv1)
	tb, db := mk(priv2)
	portA := listenPortOf(t, da)
	portB := listenPortOf(t, db)
	if err := da.IpcSet(fmt.Sprintf(
		"public_key=%s\nendpoint=127.0.0.1:%d\npersistent_keepalive_interval=1\nallowed_ip=1.0.0.2/32\n",
		pub2, portB)); err != nil {
		t.Fatalf("peer A: %v", err)
	}
	if err := db.IpcSet(fmt.Sprintf(
		"public_key=%s\nendpoint=127.0.0.1:%d\npersistent_keepalive_interval=1\nallowed_ip=1.0.0.1/32\n",
		pub1, portA)); err != nil {
		t.Fatalf("peer B: %v", err)
	}
	return ta, tb
}

// listenPortOf reads the actual UDP listen port from IpcGet after Up (listen_port=0 chose it).
func listenPortOf(t *testing.T, d *device.Device) int {
	t.Helper()
	g, err := d.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	for _, l := range strings.Split(g, "\n") {
		if v, ok := strings.CutPrefix(l, "listen_port="); ok {
			p, err := strconv.Atoi(v)
			if err != nil {
				t.Fatalf("bad listen_port %q: %v", v, err)
			}
			return p
		}
	}
	t.Fatal("no listen_port in IpcGet")
	return 0
}

func TestUDPClient_Handshake(t *testing.T) {
	a, b := newUDPDevicePair(t)
	wsAssertPing(t, a, b, [4]byte{1, 0, 0, 1}, [4]byte{1, 0, 0, 2}, 10*time.Second)
	wsAssertPing(t, b, a, [4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 1}, 10*time.Second)
}
