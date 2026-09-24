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

// wsDialTimeout bounds a whole dial: TCP connect, TLS and the WebSocket upgrade.
const wsDialTimeout = 15 * time.Second

// clientConn returns the live connection for we. When there is none it queues bufs
// and starts at most one background dial per endpoint key, returning a nil
// connection: Send must never block on network I/O, because the device calls it
// while holding the lock that BindUpdate and Close need. conns/dialing/dialBackoff
// are keyed by we.key() (dialTarget+wsURL+wstunnelTarget) so two peers sharing a
// ws_url never collide on one connection.
func (b *WebSocketBind) clientConn(we *WSEndpoint, bufs [][]byte) (*wsClientConn, error) {
	key := we.key()

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.ctx == nil {
		return nil, net.ErrClosed
	}
	if c := b.conns[key]; c != nil {
		return c, nil
	}
	if pd := b.dialing[key]; pd != nil {
		pd.enqueue(bufs)
		return nil, nil
	}
	if bo, backing := b.dialBackoff[key]; backing && bo.until.After(time.Now()) {
		return nil, fmt.Errorf("ws dial backoff for %s", we.DstToString()) // cooling down; device retries later
	}
	pd := &wsPendingDial{}
	pd.enqueue(bufs)
	b.dialing[key] = pd
	b.dialWG.Add(1)
	go b.dialAndConnect(we, key, pd, b.ctx, b.inbound, b.done)
	return nil, nil
}

// dialAndConnect runs one background dial for key. On success it publishes the
// connection, starts its read and ping loops (with the channel locals captured
// under b.mu by clientConn) and writes the queued packets in order; on failure it
// drops them and arms the endpoint's backoff.
func (b *WebSocketBind) dialAndConnect(we *WSEndpoint, key string, pd *wsPendingDial, ctx context.Context, inbound chan<- wsInbound, done <-chan struct{}) {
	defer b.dialWG.Done()

	c, err := b.dial(ctx, we)

	b.mu.Lock()
	delete(b.dialing, key) // no-op after Close, which nils the map
	if err != nil {
		if b.closed {
			b.mu.Unlock()
			return
		}
		nb := b.dialBackoff[key]
		nb.d = min(max(nb.d*2, we.backoffMin), we.backoffMax)
		if nb.d == 0 {
			nb.d = we.backoffMin
		}
		nb.until = time.Now().Add(nb.d)
		b.dialBackoff[key] = nb
		b.mu.Unlock()
		b.metrics.incConn(0, "dial_error")
		b.cfg.logger.errorf("websocket: %v", err)
		return
	}
	if b.closed {
		b.mu.Unlock()
		c.cancel()
		_ = c.wc.conn.Close()
		return
	}
	// A SetMark issued while this dial was in flight could not reach the socket yet.
	// Re-applying under b.mu means a concurrent SetMark either stored its mark before
	// this Load or finds the connection published below.
	if mark := b.mark.Load(); mark != 0 {
		if err := markConn(c.wc.conn, mark); err != nil {
			b.cfg.logger.errorf("websocket: mark new socket: %v", err)
		}
	}
	// Hold the write lock until the queue is flushed, so a Send that finds the
	// connection from now on cannot overtake the queued packets.
	c.wc.writeM.Lock()
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

	for _, buf := range pd.queue {
		if err := c.wc.writeFrameLocked(ws.OpBinary, buf); err != nil {
			b.cfg.logger.verbosef("websocket: write queued packet to %s: %v", we.DstToString(), err)
			break
		}
		b.metrics.addTx(1, uint64(len(buf)))
	}
	c.wc.writeM.Unlock()
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
			d := &net.Dialer{Timeout: wsDialTimeout, Control: b.dialControl()}
			return d.DialContext(ctx, network, target)
		},
		TLSConfig: dc.tls, // nil => plain ws://
		Protocols: dc.subprotos,
		Header:    ws.HandshakeHeaderHTTP(dc.header),
		Timeout:   wsDialTimeout,
	}
	// With a cancellable context gobwas applies Dialer.Timeout to the TCP connect only,
	// so bound the whole dial, WebSocket upgrade included, through the context.
	dctx, cancelDial := context.WithTimeout(ctx, wsDialTimeout)
	defer cancelDial()
	netConn, br, _, err := dialer.Dial(dctx, dc.dialURL)
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
