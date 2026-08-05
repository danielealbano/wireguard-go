//go:build linux && !android

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/rwcancel"
)

// netlinkMonitor watches NETLINK_ROUTE addr/route/link groups for changes. The
// !android build tag is required: GOOS=android satisfies the linux constraint but
// API 30+ forbids binding NETLINK_ROUTE sockets, so android uses the no-op monitor.
type netlinkMonitor struct {
	log    Logger
	sock   int
	cancel *rwcancel.RWCancel
}

func newWSPathMonitor(l Logger) WSPathMonitor { return &netlinkMonitor{log: l} }

func (m *netlinkMonitor) Start(onChange func()) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	if err := unix.Bind(sock, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR |
			unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE | unix.RTMGRP_LINK,
	}); err != nil {
		unix.Close(sock)
		return err
	}
	cancel, err := rwcancel.NewRWCancel(sock) // sets non-block
	if err != nil {
		unix.Close(sock)
		return err
	}
	m.sock, m.cancel = sock, cancel
	go m.loop(onChange)
	return nil
}

func (m *netlinkMonitor) loop(onChange func()) {
	defer m.cancel.Close()
	defer unix.Close(m.sock)
	debounce := newWSDebounce(300*time.Millisecond, onChange)
	defer debounce.stop()
	buf := make([]byte, 1<<16)
	for {
		var n int
		var err error
		for {
			n, _, _, _, err = unix.Recvmsg(m.sock, buf, nil, 0)
			if err == nil || !rwcancel.RetryAfterError(err) {
				break
			}
			if !m.cancel.ReadyRead() {
				return // cancelled by Close
			}
		}
		if err != nil {
			return
		}
		if n >= unix.SizeofNlMsghdr {
			debounce.trigger()
		}
	}
}

func (m *netlinkMonitor) Close() error {
	if m.cancel != nil {
		m.cancel.Cancel()
	}
	return nil
}
