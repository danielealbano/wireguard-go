/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import "time"

// PeerStats is a read-only snapshot of a peer's counters, exposed for metrics
// without leaking device internals.
type PeerStats struct {
	PublicKey         [32]byte
	Endpoint          string // DstToString of the peer's current endpoint ("" if none) — join key for WS per-endpoint stats
	TxBytes           uint64
	RxBytes           uint64
	LastHandshakeNano int64
	Connected         bool // lastHandshake recent (derived)
}

// IterPeerStats calls fn for each peer under RLock, snapshotting the existing peer
// atomics plus the endpoint string (peer.endpoint locked briefly).
func (device *Device) IterPeerStats(fn func(PeerStats)) {
	device.peers.RLock()
	defer device.peers.RUnlock()
	now := time.Now()
	for pk, peer := range device.peers.keyMap {
		peer.endpoint.Lock()
		ep := ""
		if peer.endpoint.val != nil {
			ep = peer.endpoint.val.DstToString()
		}
		peer.endpoint.Unlock()
		last := peer.lastHandshakeNano.Load()
		fn(PeerStats{
			PublicKey:         [32]byte(pk),
			Endpoint:          ep,
			TxBytes:           peer.txBytes.Load(),
			RxBytes:           peer.rxBytes.Load(),
			LastHandshakeNano: last,
			Connected:         last != 0 && now.Sub(time.Unix(0, last)) < 3*KeepaliveTimeout,
		})
	}
}

// HandshakeStats loads the handshake counters.
func (device *Device) HandshakeStats() (rateLimited, completed, failed uint64) {
	return device.handshakeRateLimited.Load(), device.handshakesCompleted.Load(), device.handshakesFailed.Load()
}
