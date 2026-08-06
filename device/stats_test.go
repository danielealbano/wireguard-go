/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

func TestDevice_HandshakeCounters(t *testing.T) {
	dev := newWSTestDevice(t, conn.NewDefaultBind(), nil)
	dev.handshakeRateLimited.Add(3)
	dev.handshakesCompleted.Add(2)
	dev.handshakesFailed.Add(1)
	rl, c, f := dev.HandshakeStats()
	if rl != 3 || c != 2 || f != 1 {
		t.Errorf("HandshakeStats = (%d,%d,%d), want (3,2,1)", rl, c, f)
	}
}

func TestDevice_IterPeerStats(t *testing.T) {
	dev := newWSTestDevice(t, conn.NewDefaultBind(), nil)
	pkHex := randKeyHex(t)
	if err := dev.IpcSet("private_key=" + randKeyHex(t) + "\npublic_key=" + pkHex + "\ntransport=udp\n"); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	var pk NoisePublicKey
	if err := pk.FromHex(pkHex); err != nil {
		t.Fatalf("FromHex: %v", err)
	}
	peer := dev.LookupPeer(pk)
	if peer == nil {
		t.Fatal("peer not found")
	}
	peer.txBytes.Store(100)
	peer.rxBytes.Store(200)

	var got []PeerStats
	dev.IterPeerStats(func(p PeerStats) { got = append(got, p) })
	if len(got) != 1 {
		t.Fatalf("got %d peer stats, want 1", len(got))
	}
	if got[0].TxBytes != 100 || got[0].RxBytes != 200 {
		t.Errorf("tx/rx = %d/%d, want 100/200", got[0].TxBytes, got[0].RxBytes)
	}
	if got[0].PublicKey != [32]byte(pk) {
		t.Error("public key mismatch")
	}
	if got[0].Connected {
		t.Error("peer with no handshake should not be Connected")
	}
}
