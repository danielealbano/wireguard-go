/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/gobwas/ws"
)

// clientConn returns the live connection for we, dialing once on demand. The read
// and ping loops are started here with the channel locals captured under b.mu.
// conns/dialBackoff are keyed by we.key() (dialTarget+wsURL+wstunnelTarget) so two
// peers sharing a ws_url never collide on one connection.
func (b *WebSocketBind) clientConn(we *WSEndpoint) (*wsClientConn, error) {
	b.dialM.Lock()
	defer b.dialM.Unlock()

	key := we.key()

	b.mu.Lock()
	closed := b.closed
	existing := b.conns[key]
	inbound, done, ctx := b.inbound, b.done, b.ctx
	bo, backing := b.dialBackoff[key]
	b.mu.Unlock()

	if closed {
		return nil, net.ErrClosed
	}
	if existing != nil {
		return existing, nil
	}
	if backing && bo.until.After(time.Now()) {
		return nil, fmt.Errorf("ws dial backoff for %s", we.DstToString()) // cooling down; device retries later
	}

	c, err := b.dial(ctx, we)

	b.mu.Lock()
	if err != nil {
		nb := b.dialBackoff[key]
		nb.d = min(max(nb.d*2, we.backoffMin), we.backoffMax)
		if nb.d == 0 {
			nb.d = we.backoffMin
		}
		nb.until = time.Now().Add(nb.d)
		b.dialBackoff[key] = nb
		b.mu.Unlock()
		b.metrics.incConn(0, "dial_error")
		return nil, err
	}
	if b.closed {
		b.mu.Unlock()
		_ = c.wc.conn.Close()
		return nil, net.ErrClosed
	}
	delete(b.dialBackoff, key) // success resets backoff
	b.conns[key] = c
	b.readWG.Add(2) // readLoop + pingLoop
	b.mu.Unlock()

	b.metrics.incConn(1, "ok")
	go func() {
		defer b.readWG.Done()
		b.readLoop(c, inbound, done)
		b.metrics.incConn(-1, "")
	}()
	go func() {
		defer b.readWG.Done()
		b.pingLoop(c)
	}()
	return c, nil
}

func (b *WebSocketBind) dial(ctx context.Context, we *WSEndpoint) (*wsClientConn, error) {
	dc, err := we.dialConfig()
	if err != nil {
		return nil, err
	}
	target := we.dialTarget.String()
	dialer := ws.Dialer{
		NetDial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Connect to the resolved endpoint ip:port, NOT the URL host — the URL
			// host is used only for TLS SNI / the HTTP Host header (via dc). This is
			// what lets wg-quick host-route the exact dialed IP and avoids any
			// A-record mismatch between the tools' resolution and ours.
			d := &net.Dialer{Timeout: 15 * time.Second, Control: b.dialControl()}
			return d.DialContext(ctx, network, target)
		},
		TLSConfig: dc.tls, // nil => plain ws://
		Protocols: dc.subprotos,
		Header:    ws.HandshakeHeaderHTTP(dc.header),
		Timeout:   15 * time.Second,
	}
	netConn, br, _, err := dialer.Dial(ctx, dc.dialURL)
	if err != nil {
		return nil, fmt.Errorf("ws dial %s: %w", we.DstToString(), err)
	}
	if br == nil {
		br = bufio.NewReader(netConn) // gobwas returns nil when nothing was buffered past the handshake
	}
	cctx, cancel := context.WithCancel(ctx)
	return &wsClientConn{
		wc:     &wsConn{conn: netConn, br: br, mask: we.mask},
		ep:     we,
		ctx:    cctx,
		cancel: cancel,
		pong:   make(chan struct{}, 1),
	}, nil
}
