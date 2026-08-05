/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"crypto/rand"
	"fmt"
	"net"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// wstunnelClaims embeds jwt.RegisteredClaims to satisfy the jwt.Claims interface;
// the wstunnel-specific fields are non-registered. timeout is *int so it marshals
// to JSON null for the UDP protocol variant.
type wstunnelClaims struct {
	ID string        `json:"id"`
	P  wstunnelProto `json:"p"`
	R  string        `json:"r"`
	RP int           `json:"rp"`
	jwt.RegisteredClaims
}

type wstunnelProto struct {
	Udp struct {
		Timeout *int `json:"timeout"`
	} `json:"Udp"`
}

func wsRandomSecret() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand; never returns an error on supported platforms
	return b
}

// wstunnelJWT builds the HS256 token. The wstunnel server does NOT verify the
// signature, but the token must be a well-formed HS256 JWT — golang-jwt guarantees that.
func wstunnelJWT(wstunnelTarget string, secret []byte) (string, error) {
	host, portStr, err := net.SplitHostPort(wstunnelTarget)
	if err != nil {
		return "", fmt.Errorf("wstunnel_target %q: %w", wstunnelTarget, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("wstunnel_target port %q: %w", portStr, err)
	}
	claims := wstunnelClaims{ID: uuid.NewString(), R: host, RP: port}
	// claims.P.Udp.Timeout stays nil => JSON null.
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}
