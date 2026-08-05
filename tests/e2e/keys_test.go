//go:build linux && e2e

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// genKeypair returns a clamped Curve25519 private key and its public key, hex-encoded
// for the UAPI private_key=/public_key= lines.
func genKeypair(t *testing.T) (privHex, pubHex string) {
	t.Helper()
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	return hex.EncodeToString(sk[:]), hex.EncodeToString(pk)
}
