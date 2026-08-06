/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"time"

	"github.com/gobwas/ws"
)

// pingLoop writes an OpPing every ep.pingInterval and waits for the read loop to
// signal the matching pong, bounded by that interval so a silent/half-open peer (no
// pong) is detected. On write failure or pong timeout it closes the connection —
// unblocking the read loop so the next Send re-dials — and cancels the per-connection
// ctx. It exits when that ctx is cancelled (drop or bind Close). It records RTT.
func (b *WebSocketBind) pingLoop(c *wsClientConn) {
	if c.ep.pingInterval <= 0 {
		return
	}
	t := time.NewTicker(c.ep.pingInterval)
	defer t.Stop()
	fail := func(format string, args ...any) {
		if c.ctx.Err() == nil { // a real ping failure/timeout, not a bind close
			b.cfg.logger.verbosef(format, args...)
			c.cancel()
			_ = c.wc.conn.Close()
		}
	}
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			start := time.Now()
			if err := c.wc.writeFrame(ws.OpPing, wsPingPayload); err != nil {
				fail("websocket ping to %s failed, will reconnect: %v", c.ep.DstToString(), err)
				return
			}
			select {
			case <-c.pong:
				b.metrics.observeRTT(c.ep.DstToString(), time.Since(start).Seconds())
			case <-time.After(c.ep.pingInterval):
				fail("websocket pong from %s timed out, will reconnect", c.ep.DstToString())
				return
			case <-c.ctx.Done():
				return
			}
		}
	}
}
