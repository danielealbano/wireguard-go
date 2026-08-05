/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"time"
)

// pingLoop pings the connection every cfg.pingInterval; each ping is bounded by a
// timeout so a silent/half-open peer (no pong) is detected. On failure it cancels
// the connection, which unblocks its read loop and makes the next Send re-dial. It
// exits when the per-connection ctx is cancelled (drop or bind Close). It records RTT.
func (b *WebSocketBind) pingLoop(c *wsClientConn) {
	if b.cfg.pingInterval <= 0 {
		return
	}
	t := time.NewTicker(b.cfg.pingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			start := time.Now()
			pingCtx, cancel := context.WithTimeout(c.ctx, b.cfg.pingInterval)
			err := c.conn.Ping(pingCtx)
			cancel()
			if err != nil {
				if c.ctx.Err() == nil { // a real ping failure/timeout, not a bind close
					b.cfg.logger.verbosef("websocket ping to %s failed, will reconnect: %v", c.ep.DstToString(), err)
					c.cancel() // triggers read-loop exit + reconnect
				}
				return
			}
			b.metrics.observeRTT(c.ep.DstToString(), time.Since(start).Seconds())
		}
	}
}
