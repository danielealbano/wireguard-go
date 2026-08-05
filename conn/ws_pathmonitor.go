/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"sync"
	"time"
)

// WSPathMonitor watches for OS network-path changes and invokes onChange (which
// the daemon wires to device.BindUpdate). Standalone daemon only; embedded apps
// drive BindUpdate themselves.
type WSPathMonitor interface {
	Start(onChange func()) error
	Close() error
}

// NewWSPathMonitor returns the per-OS standalone path monitor.
func NewWSPathMonitor(l Logger) WSPathMonitor { return newWSPathMonitor(l) }

// wsDebounce coalesces a burst of change events into a single onChange after a
// quiet period. Shared by the platform monitors; also the unit-testable core.
type wsDebounce struct {
	d  time.Duration
	fn func()
	mu sync.Mutex
	t  *time.Timer
}

func newWSDebounce(d time.Duration, fn func()) *wsDebounce { return &wsDebounce{d: d, fn: fn} }

func (w *wsDebounce) trigger() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.t == nil {
		w.t = time.AfterFunc(w.d, w.fn)
	} else {
		w.t.Reset(w.d)
	}
}

func (w *wsDebounce) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.t != nil {
		w.t.Stop()
	}
}
