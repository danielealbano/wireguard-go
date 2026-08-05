/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "testing"

// TestWSEndpoint_WSConfig covers the gating IpcGet relies on: only client, URL-configured
// endpoints report their ws_mode/ws_target/ws_bearer; a server inbound endpoint (no URL)
// reports ok=false so IpcGet emits nothing for it.
func TestWSEndpoint_WSConfig(t *testing.T) {
	tests := []struct {
		name                             string
		e                                WSEndpoint
		wantMode, wantTarget, wantBearer string
		wantOK                           bool
	}{
		{
			name:   "server inbound (no url)",
			e:      WSEndpoint{dialect: wsDialectStandard, target: "ignored", bearer: "ignored"},
			wantOK: false,
		},
		{
			name:     "client standard",
			e:        WSEndpoint{url: "wss://server.example.com/wg", dialect: wsDialectStandard},
			wantMode: "standard",
			wantOK:   true,
		},
		{
			name:       "client wstunnel with target and bearer",
			e:          WSEndpoint{url: "wss://relay.example.com:8443", dialect: wsDialectWstunnel, target: "10.0.0.9:51820", bearer: "tok"},
			wantMode:   "wstunnel",
			wantTarget: "10.0.0.9:51820",
			wantBearer: "tok",
			wantOK:     true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mode, target, bearer, ok := tc.e.WSConfig()
			if ok != tc.wantOK || mode != tc.wantMode || target != tc.wantTarget || bearer != tc.wantBearer {
				t.Errorf("WSConfig() = (%q, %q, %q, %v), want (%q, %q, %q, %v)",
					mode, target, bearer, ok, tc.wantMode, tc.wantTarget, tc.wantBearer, tc.wantOK)
			}
		})
	}
}
