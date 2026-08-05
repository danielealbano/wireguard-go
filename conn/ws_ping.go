/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "time"

// pingLoop pings the connection every cfg.pingInterval; on failure it cancels the
// connection, which unblocks its read loop and makes the next Send re-dial. It exits
// when the per-connection ctx is cancelled (drop or bind Close). It records the RTT.
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
			if err := c.conn.Ping(c.ctx); err != nil {
				c.cancel() // triggers read-loop exit + reconnect
				return
			}
			b.metrics.observeRTT(c.ep.DstToString(), time.Since(start).Seconds())
		}
	}
}
