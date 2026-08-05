//go:build darwin

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import "testing"

func TestWSIsIPv6(t *testing.T) {
	if !wsIsIPv6("[2001:db8::1]:443") {
		t.Error("v6 address not detected")
	}
	if wsIsIPv6("1.2.3.4:443") {
		t.Error("v4 address misdetected as v6")
	}
}
