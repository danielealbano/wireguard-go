/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/coder/websocket"
)

func (b *WebSocketBind) openServer(ctx context.Context, port uint16, inbound chan wsInbound, done <-chan struct{}) ([]ReceiveFunc, uint16, error) {
	u, err := url.Parse(b.cfg.listenURL)
	if err != nil {
		return nil, 0, err
	}
	b.sconns = make(map[uint64]*wsServerConn)
	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		if !b.checkBearer(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		dst := resolveClientAddr(r, b.cfg.trustedProxies)
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			c.CloseNow()
			return
		}
		b.nextConnID++
		id := b.nextConnID
		sc := &wsServerConn{conn: c, id: id, ctx: ctx}
		b.sconns[id] = sc
		b.readWG.Add(1) // under b.mu with the closed check (no WaitGroup misuse)
		b.mu.Unlock()
		b.metrics.incConn(1, "ok")
		defer func() {
			b.readWG.Done()
			b.metrics.incConn(-1, "")
		}()
		b.serverReadLoop(sc, &WSEndpoint{dst: dst, connID: id}, inbound, done)
	})
	b.srv = &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", u.Host)
	if err != nil {
		return nil, 0, err
	}
	go func() {
		if b.cfg.tlsServer != nil {
			b.srv.TLSConfig = b.cfg.tlsServer
			_ = b.srv.ServeTLS(ln, "", "") // certs come from tlsServer
		} else {
			_ = b.srv.Serve(ln)
		}
	}()
	return []ReceiveFunc{makeWSReceiveFunc(inbound, done)}, port, nil
}

func (b *WebSocketBind) checkBearer(r *http.Request) bool {
	if b.cfg.serverBearer == "" {
		return true // gate off (no bearer configured)
	}
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(p) || h[:len(p)] != p {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h[len(p):]), []byte(b.cfg.serverBearer)) == 1
}

func (b *WebSocketBind) serverReadLoop(sc *wsServerConn, ep *WSEndpoint, inbound chan<- wsInbound, done <-chan struct{}) {
	sc.conn.SetReadLimit(wsReadLimit)
	defer func() {
		b.mu.Lock()
		if b.sconns[sc.id] == sc {
			delete(b.sconns, sc.id)
		}
		b.mu.Unlock()
		sc.conn.CloseNow()
	}()
	for {
		typ, data, err := sc.conn.Read(sc.ctx) // per-conn ctx captured at accept (no b.ctx field race)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			continue
		}
		select {
		case inbound <- wsInbound{data: data, ep: ep}:
			b.metrics.addRx(1, uint64(len(data)))
		case <-done:
			return
		default:
			b.metrics.drop("queue_full")
		}
	}
}

func (b *WebSocketBind) serverSend(bufs [][]byte, we *WSEndpoint) error {
	b.mu.Lock()
	sc := b.sconns[we.connID]
	b.mu.Unlock()
	if sc == nil {
		return fmt.Errorf("no active websocket connection for peer (id %d)", we.connID)
	}
	sc.writeM.Lock()
	defer sc.writeM.Unlock()
	for _, buf := range bufs {
		if err := sc.conn.Write(sc.ctx, websocket.MessageBinary, buf); err != nil {
			return err
		}
		b.metrics.addTx(1, uint64(len(buf)))
	}
	return nil
}
