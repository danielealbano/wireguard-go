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
// dialBackoff is read/written under b.mu (same discipline as b.conns) so it can
// never race with Open's reassignment on a BindUpdate; dialM serialises the dial.
func (b *WebSocketBind) clientConn(we *WSEndpoint) (*wsClientConn, error) {
	b.dialM.Lock()
	defer b.dialM.Unlock()

	b.mu.Lock()
	closed := b.closed
	existing := b.conns[we.url]
	inbound, done, ctx := b.inbound, b.done, b.ctx
	bo, backing := b.dialBackoff[we.url]
	b.mu.Unlock()

	if closed {
		return nil, net.ErrClosed
	}
	if existing != nil {
		return existing, nil
	}
	if backing && bo.until.After(time.Now()) {
		return nil, fmt.Errorf("ws dial backoff for %s", we.url) // cooling down; device retries later
	}

	c, err := b.dial(ctx, we)

	b.mu.Lock()
	if err != nil {
		nb := b.dialBackoff[we.url]
		nb.d = min(max(nb.d*2, b.cfg.backoffMin), b.cfg.backoffMax)
		if nb.d == 0 {
			nb.d = b.cfg.backoffMin
		}
		nb.until = time.Now().Add(nb.d)
		b.dialBackoff[we.url] = nb
		b.mu.Unlock()
		b.metrics.incConn(0, "dial_error")
		return nil, err
	}
	if b.closed {
		b.mu.Unlock()
		_ = c.wc.conn.Close()
		return nil, net.ErrClosed
	}
	delete(b.dialBackoff, we.url) // success resets backoff
	b.conns[we.url] = c
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
	dialURL, header, subprotos, err := wsUpgradeRequest(we)
	if err != nil {
		return nil, err
	}
	dialer := ws.Dialer{
		NetDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 15 * time.Second, Control: b.dialControl()}
			return d.DialContext(ctx, network, addr)
		},
		TLSConfig: b.cfg.tlsClient, // nil => system roots (gobwas tlsDefaultConfig, SNI from host)
		Protocols: subprotos,
		Header:    ws.HandshakeHeaderHTTP(header),
		Timeout:   15 * time.Second,
	}
	netConn, br, _, err := dialer.Dial(ctx, dialURL)
	if err != nil {
		return nil, fmt.Errorf("ws dial %s: %w", we.url, err)
	}
	if br == nil {
		br = bufio.NewReader(netConn) // gobwas returns nil when nothing was buffered past the handshake
	}
	cctx, cancel := context.WithCancel(ctx)
	return &wsClientConn{
		wc:     &wsConn{conn: netConn, br: br, mask: b.cfg.maskFrames},
		ep:     we,
		ctx:    cctx,
		cancel: cancel,
		pong:   make(chan struct{}, 1),
	}, nil
}
