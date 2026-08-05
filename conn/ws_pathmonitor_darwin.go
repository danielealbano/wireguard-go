//go:build darwin && cgo

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

/*
#cgo LDFLAGS: -framework Network -framework CoreFoundation
#include <Network/Network.h>
#include <dispatch/dispatch.h>

extern void wsPathChangedGo(uintptr_t handle);

static nw_path_monitor_t wsStartPathMonitor(uintptr_t handle) {
	nw_path_monitor_t m = nw_path_monitor_create();
	dispatch_queue_t q = dispatch_queue_create("com.wireguard.ws.pathmonitor", DISPATCH_QUEUE_SERIAL);
	nw_path_monitor_set_queue(m, q);
	nw_path_monitor_set_update_handler(m, ^(nw_path_t path) {
		if (nw_path_get_status(path) == nw_path_status_satisfied) {
			wsPathChangedGo(handle);
		}
	});
	nw_path_monitor_start(m);
	return m;
}

static void wsStopPathMonitor(nw_path_monitor_t m) { nw_path_monitor_cancel(m); }
*/
import "C"

import (
	"runtime/cgo"
	"sync"
	"time"
)

// nwMonitor bridges Apple's NWPathMonitor (Network.framework) to onChange. Verified
// against the SDK Network.framework path_monitor.h (all API_AVAILABLE(macos(10.14))).
type nwMonitor struct {
	log      Logger
	mu       sync.Mutex
	mon      C.nw_path_monitor_t
	handle   cgo.Handle
	started  bool
	debounce *wsDebounce
}

func newWSPathMonitor(l Logger) WSPathMonitor { return &nwMonitor{log: l} }

func (m *nwMonitor) Start(onChange func()) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil
	}
	m.debounce = newWSDebounce(300*time.Millisecond, onChange)
	m.handle = cgo.NewHandle(m)
	m.mon = C.wsStartPathMonitor(C.uintptr_t(m.handle))
	m.started = true
	return nil
}

func (m *nwMonitor) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.started {
		return nil
	}
	C.wsStopPathMonitor(m.mon)
	m.handle.Delete()
	if m.debounce != nil {
		m.debounce.stop()
	}
	m.started = false
	return nil
}

//export wsPathChangedGo
func wsPathChangedGo(handle C.uintptr_t) {
	if m, ok := cgo.Handle(handle).Value().(*nwMonitor); ok && m.debounce != nil {
		m.debounce.trigger()
	}
}
