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

	"github.com/gobwas/ws"
)

func (b *WebSocketBind) openServer(ctx context.Context, port uint16, inbound chan wsInbound, done <-chan struct{}) ([]ReceiveFunc, uint16, error) {
	// openServer is called from Open under b.mu, so this read is synchronized with
	// SetWSListen; capture a local so the serve goroutine below never touches the field.
	listenURL := b.cfg.listenURL
	u, err := url.Parse(listenURL)
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
		netConn, rw, _, err := ws.HTTPUpgrader{Protocol: func(p string) bool { return p == "v1" }}.Upgrade(r, w)
		if err != nil {
			return
		}
		dst := resolveClientAddr(r, b.cfg.trustedProxies)
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			_ = netConn.Close()
			return
		}
		b.nextConnID++
		id := b.nextConnID
		sc := &wsServerConn{wc: &wsConn{conn: netConn, br: rw.Reader}, id: id}
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
	srv := &http.Server{Handler: mux}
	if b.cfg.tlsServer != nil {
		srv.TLSConfig = b.cfg.tlsServer // certs come from tlsServer
	}
	b.srv = srv // stored under b.mu (Open); Close reads it under b.mu to shut down
	ln, err := net.Listen("tcp", u.Host)
	if err != nil {
		return nil, 0, err
	}
	// The serve goroutine references only the srv/ln locals — never the b.srv field —
	// so Close nil-ing b.srv cannot race with it. It is tracked on readWG so Close's
	// Wait() joins it: srv.Close() makes Serve return and release the listener, so the
	// port is free before Close returns (required for a BindUpdate re-Open on the same
	// listen address). Add is under b.mu (Open) with the closed check, like the others.
	b.readWG.Add(1)
	go func() {
		defer b.readWG.Done()
		var serveErr error
		if b.cfg.tlsServer != nil {
			serveErr = srv.ServeTLS(ln, "", "")
		} else {
			serveErr = srv.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			b.cfg.logger.errorf("websocket server on %s stopped: %v", listenURL, serveErr)
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
	defer func() {
		b.mu.Lock()
		if b.sconns[sc.id] == sc {
			delete(b.sconns, sc.id)
		}
		b.mu.Unlock()
		_ = sc.wc.conn.Close()
	}()
	for {
		data, err := sc.wc.readMessage(wsReadLimit, nil) // accepts masked or unmasked; answers pings
		if err != nil {
			return
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
	for _, buf := range bufs {
		if err := sc.wc.writeFrame(ws.OpBinary, buf); err != nil { // writeFrame serialises on wc.writeM
			return err
		}
		b.metrics.addTx(1, uint64(len(buf)))
	}
	return nil
}
