/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"net"

	"github.com/gobwas/ws"
)

// Concurrency contract (avoids send-on-closed-channel panics):
//   - b.inbound is NEVER closed. Shutdown is signalled by closing b.done.
//   - Every read/ping loop registers on b.readWG; Close closes b.done, CloseNow's
//     the sockets to unblock reads, then b.readWG.Wait() joins all producers BEFORE
//     returning — no leak across Close/Open (BindUpdate) cycles.

func (b *WebSocketBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.inbound != nil {
		return nil, 0, ErrBindAlreadyOpen
	}
	b.closed = false
	inbound := make(chan wsInbound, 128)
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	b.inbound, b.done, b.ctx, b.ctxCancel = inbound, done, ctx, cancel
	if b.cfg.role == WSRoleServer {
		return b.openServer(ctx, port, inbound, done)
	}
	b.conns = make(map[string]*wsClientConn)
	b.dialBackoff = make(map[string]wsBackoff)
	return []ReceiveFunc{makeWSReceiveFunc(inbound, done)}, port, nil
}

// makeWSReceiveFunc closes over the channels as locals (captured under b.mu in Open),
// so the returned func never reads the b.done/b.inbound fields — no race with Close
// reassigning them across a BindUpdate (Close then Open) cycle.
func makeWSReceiveFunc(inbound <-chan wsInbound, done <-chan struct{}) ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (int, error) {
		select {
		case <-done:
			return 0, net.ErrClosed
		case in := <-inbound:
			if len(in.data) > len(bufs[0]) { // oversize guard: drop, don't truncate
				return 0, nil
			}
			sizes[0] = copy(bufs[0], in.data)
			eps[0] = in.ep
			return 1, nil
		}
	}
}

func (b *WebSocketBind) Send(bufs [][]byte, ep Endpoint) error {
	we, ok := ep.(*WSEndpoint)
	if !ok {
		return ErrWrongEndpointType
	}
	if b.cfg.role == WSRoleServer {
		return b.serverSend(bufs, we)
	}
	c, err := b.clientConn(we)
	if err != nil {
		return err
	}
	for _, buf := range bufs {
		if err := c.wc.writeFrame(ws.OpBinary, buf); err != nil { // writeFrame serialises on wc.writeM
			return err
		}
		b.metrics.addTx(1, uint64(len(buf)))
	}
	return nil
}

// readLoop delivers inbound binary messages from a client connection to the shared
// queue. inbound/done are captured from b under b.mu at dial time and passed in —
// never read from the fields in the loop, to stay race-free with Open/Close.
func (b *WebSocketBind) readLoop(c *wsClientConn, inbound chan<- wsInbound, done <-chan struct{}) {
	defer func() {
		b.mu.Lock()
		if b.conns[c.ep.url] == c {
			delete(b.conns, c.ep.url)
		}
		b.mu.Unlock()
		c.cancel()
		_ = c.wc.conn.Close()
	}()
	onPong := func() {
		select {
		case c.pong <- struct{}{}:
		default:
		}
	}
	for {
		data, err := c.wc.readMessage(wsReadLimit, onPong)
		if err != nil {
			if !b.isClosed() {
				b.cfg.logger.verbosef("websocket read on %s ended, will reconnect: %v", c.ep.DstToString(), err)
				b.metrics.incReconnect(c.ep.DstToString())
			}
			return
		}
		select {
		case inbound <- wsInbound{data: data, ep: c.ep}:
			b.metrics.addRx(1, uint64(len(data)))
		case <-done:
			return
		default:
			b.metrics.drop("queue_full")
		}
	}
}

func (b *WebSocketBind) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// Close is canonical for both roles. b.mu MUST be released before readWG.Wait():
// the read loops reacquire b.mu to deregister, so holding it across Wait() would
// deadlock. b.inbound is NEVER closed, so no producer can panic.
func (b *WebSocketBind) Close() error {
	b.mu.Lock()
	if b.closed || b.done == nil {
		b.mu.Unlock()
		return nil // idempotent
	}
	b.closed = true
	close(b.done) // unblocks every ReceiveFunc with net.ErrClosed
	if b.ctxCancel != nil {
		b.ctxCancel() // unblocks all read loops (they read with the per-conn ctx)
	}
	srv := b.srv
	// Detach the registries under the lock BEFORE ranging them: the read loops we
	// are about to unblock deregister via delete(b.conns/b.sconns, ...) under b.mu,
	// which on a nil field is a safe no-op — so no goroutine iterates or writes the
	// same map concurrently.
	clients := b.conns
	servers := b.sconns
	b.conns, b.sconns = nil, nil
	b.mu.Unlock()

	if srv != nil {
		_ = srv.Close() // stops the listener + Accept handlers (server role)
	}
	for _, c := range clients {
		_ = c.wc.conn.Close() // idempotent; the read loop may also close it
	}
	for _, sc := range servers {
		_ = sc.wc.conn.Close()
	}
	b.readWG.Wait() // join all read/ping loops

	b.mu.Lock()
	b.inbound, b.done, b.srv = nil, nil, nil
	b.mu.Unlock()
	return nil
}
