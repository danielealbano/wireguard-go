/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "fmt"

// NewBindForTransport selects the bind at startup (keeps main thin and testable):
// "" or "udp" -> the default UDP bind; "ws" -> a WebSocket bind; anything else errors.
func NewBindForTransport(transport string, opts ...WSOption) (Bind, error) {
	switch transport {
	case "", "udp":
		return NewDefaultBind(), nil
	case "ws":
		return NewWebSocketBind(opts...)
	default:
		return nil, fmt.Errorf("invalid WG_TRANSPORT %q (want udp|ws)", transport)
	}
}
