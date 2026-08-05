//go:build darwin && !cgo

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

// noopMonitor is used on darwin when cgo is disabled (the NWPathMonitor bridge
// needs cgo). CGO-off / cross-compiled darwin builds fall back to the no-op; the
// full release binaries are built with cgo on a macOS runner.
type noopMonitor struct{}

func newWSPathMonitor(l Logger) WSPathMonitor { return noopMonitor{} }

func (noopMonitor) Start(onChange func()) error { return nil }
func (noopMonitor) Close() error                { return nil }
