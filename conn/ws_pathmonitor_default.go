//go:build (!linux && !darwin) || android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

// noopMonitor is the standalone path monitor for platforms without an in-process
// path-change source. The android term is required so android (which satisfies the
// linux constraint) gets this no-op instead of the netlink monitor; API 30+ forbids
// binding NETLINK_ROUTE sockets, so the app drives BindUpdate itself.
type noopMonitor struct{}

func newWSPathMonitor(l Logger) WSPathMonitor { return noopMonitor{} }

func (noopMonitor) Start(onChange func()) error { return nil }
func (noopMonitor) Close() error                { return nil }
