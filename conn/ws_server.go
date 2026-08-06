/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/gobwas/ws"
)

// openServer starts the HTTP/WS listener for ws_listen. It is called from Open
// under b.mu (only when ws_listen is set); it captures the device-level server
// config into per-serve LOCALS so the serve goroutine and per-request handlers
// close over immutable copies — a later UAPI change takes effect on the next
// BindUpdate re-open, avoiding races with the server setters.
func (b *WebSocketBind) openServer(inbound chan wsInbound, done <-chan struct{}) error {
	listenURL := b.cfg.listenURL
	serverBearer := b.cfg.serverBearer
	trustedProxies := b.cfg.trustedProxies
	certPath, keyPath := b.cfg.serverCertPath, b.cfg.serverKeyPath

	u, err := url.Parse(listenURL)
	if err != nil {
		return err
	}
	if u.Path == "" {
		u.Path = "/" // http.ServeMux panics on an empty pattern
	}

	var tlsConfig *tls.Config
	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return fmt.Errorf("ws server tls: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	b.sconns = make(map[uint64]*wsServerConn)
	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r, serverBearer) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		netConn, rw, _, err := ws.HTTPUpgrader{Protocol: func(p string) bool { return p == "v1" }}.Upgrade(r, w)
		if err != nil {
			return
		}
		// Mark the accepted socket so a server under a full-tunnel fwmark rule keeps
		// its replies off the tun (server-side parity with client dial marking;
		// no-op on darwin/windows).
		if err := markConn(netConn, b.mark.Load()); err != nil {
			b.cfg.logger.errorf("websocket: mark accepted socket: %v", err)
		}
		dst := resolveClientAddr(r, trustedProxies)
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
	if tlsConfig != nil {
		srv.TLSConfig = tlsConfig
	}
	b.srv = srv // stored under b.mu (Open); Close reads it under b.mu to shut down
	ln, err := net.Listen("tcp", u.Host)
	if err != nil {
		return err
	}
	// The serve goroutine references only srv/ln/useTLS locals — never b.srv or
	// b.cfg.serverCertPath — so Close nil-ing b.srv and a concurrent SetServerTLS
	// cannot race with it. Tracked on readWG so Close's Wait() joins it.
	useTLS := tlsConfig != nil
	b.readWG.Add(1)
	go func() {
		defer b.readWG.Done()
		var serveErr error
		if useTLS {
			serveErr = srv.ServeTLS(ln, "", "")
		} else {
			serveErr = srv.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			b.cfg.logger.errorf("websocket server on %s stopped: %v", listenURL, serveErr)
		}
	}()
	return nil
}

// checkBearer is a coarse constant-time gate; expected is the captured per-serve
// local (empty => gate off). The bearer value is NEVER logged.
func checkBearer(r *http.Request, expected string) bool {
	if expected == "" {
		return true
	}
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(p) || h[:len(p)] != p {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h[len(p):]), []byte(expected)) == 1
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
