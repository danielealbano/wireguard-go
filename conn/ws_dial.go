/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
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
		c.conn.CloseNow()
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
	dialer := &net.Dialer{Timeout: 15 * time.Second, Control: b.dialControl()}
	tr := &http.Transport{
		DialContext:     dialer.DialContext,
		TLSClientConfig: b.cfg.tlsClient, // nil => system roots
	}
	conn, _, err := websocket.Dial(ctx, dialURL, &websocket.DialOptions{
		HTTPClient:   &http.Client{Transport: tr},
		HTTPHeader:   header,
		Subprotocols: subprotos,
	})
	if err != nil {
		return nil, fmt.Errorf("ws dial %s: %w", we.url, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	return &wsClientConn{conn: conn, ep: we, ctx: cctx, cancel: cancel}, nil
}
