/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/gobwas/ws"
)

// errWSOversize is returned when an inbound WebSocket message exceeds wsReadLimit.
var errWSOversize = errors.New("websocket message exceeds read limit")

// wsPingPayload is the (small) application data carried by keepalive pings.
var wsPingPayload = []byte("wg")

// wsConn wraps a dialed/hijacked net.Conn with the *bufio.Reader that holds any
// bytes buffered during the WebSocket handshake. Reads use br; writes go to conn.
// mask is set only for the client role when ws_mask is enabled (servers never mask).
type wsConn struct {
	conn   net.Conn
	br     *bufio.Reader
	writeM sync.Mutex
	mask   bool
}

// writeFrame writes one WebSocket frame, honouring the masking policy. Unmasked
// writes are zero-copy; masking copies the payload first (MaskFrameInPlace mutates it).
func (c *wsConn) writeFrame(op ws.OpCode, payload []byte) error {
	c.writeM.Lock()
	defer c.writeM.Unlock()
	if c.mask {
		p := append([]byte(nil), payload...)
		return ws.WriteFrame(c.conn, ws.MaskFrameInPlace(ws.NewFrame(op, true, p)))
	}
	return ws.WriteFrame(c.conn, ws.NewFrame(op, true, payload))
}

// readMessage returns the next binary application message, reassembling fragments and
// enforcing limit before allocation. It answers pings with pongs and reports pongs via
// onPong (may be nil). Non-binary data messages are discarded. OpClose returns io.EOF.
func (c *wsConn) readMessage(limit int64, onPong func()) ([]byte, error) {
	var msg []byte
	var msgOp ws.OpCode
	for {
		h, err := ws.ReadHeader(c.br)
		if err != nil {
			return nil, err
		}
		if h.Length > limit || int64(len(msg))+h.Length > limit {
			return nil, errWSOversize
		}
		payload := make([]byte, h.Length)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return nil, err
		}
		if h.Masked {
			ws.Cipher(payload, h.Mask, 0)
		}
		switch h.OpCode {
		case ws.OpPing:
			if err := c.writeFrame(ws.OpPong, payload); err != nil {
				return nil, err
			}
		case ws.OpPong:
			if onPong != nil {
				onPong()
			}
		case ws.OpClose:
			return nil, io.EOF
		case ws.OpBinary, ws.OpText:
			msgOp = h.OpCode
			msg = append(msg[:0], payload...)
			if h.Fin {
				if msgOp != ws.OpBinary {
					msg = msg[:0]
					continue
				}
				return msg, nil
			}
		case ws.OpContinuation:
			msg = append(msg, payload...)
			if h.Fin {
				if msgOp != ws.OpBinary {
					msg = msg[:0]
					continue
				}
				return msg, nil
			}
		}
	}
}
