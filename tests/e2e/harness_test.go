//go:build linux && e2e

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package e2e

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

// requireRootLinux skips unless the test runs as root on Linux (netns needs CAP_NET_ADMIN).
func requireRootLinux(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("e2e netns tests require root")
	}
}

// wgBin is the wireguard-go binary under test, provided by the Makefile (WG_GO_BIN).
// requireRootLinux has already passed by the time this is called, so an empty value
// means the Makefile env was NOT preserved through sudo — FAIL loudly rather than
// t.Skip, which would green a privileged CI job that actually ran nothing.
func wgBin(t *testing.T) string {
	t.Helper()
	p := os.Getenv("WG_GO_BIN")
	if p == "" {
		t.Fatal("WG_GO_BIN not set (run via `make test-e2e`; env must survive sudo)")
	}
	return p
}

// ifaceSeq gives every daemon a unique, short (<=15 char) interface name across the
// WHOLE test binary, so UAPI sockets on the shared filesystem never collide between
// the sequential e2e tests.
var ifaceSeq atomic.Int32

type lab struct {
	t     *testing.T
	ns    []string
	procs []*exec.Cmd
	socks []string // UAPI socket paths to remove on cleanup (SIGKILL leaves them behind)
}

func newLab(t *testing.T) *lab {
	requireRootLinux(t)
	l := &lab{t: t}
	t.Cleanup(l.cleanup)
	return l
}

// run executes a command, failing the test on error (used for setup that must succeed).
func (l *lab) run(name string, args ...string) {
	l.t.Helper()
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		l.t.Fatalf("%s %v: %v (%s)", name, args, err, stderr.String())
	}
}

func (l *lab) addNS() string {
	ns := fmt.Sprintf("wgtns%d", ifaceSeq.Add(1))
	l.run("ip", "netns", "add", ns)
	l.ns = append(l.ns, ns)
	return ns
}

func (l *lab) addBridge() string {
	name := fmt.Sprintf("wgbr%d", ifaceSeq.Add(1))
	l.run("ip", "link", "add", name, "type", "bridge")
	l.run("ip", "link", "set", name, "up")
	l.t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })
	return name
}

// vethToBridge connects namespace ns to the bridge brName with address cidr, using a
// globally-unique veth name so it never collides with a prior (possibly not-yet-torn-down)
// test's interfaces on the shared root namespace.
func (l *lab) vethToBridge(ns, brName, cidr string) {
	ifname := fmt.Sprintf("wgv%d", ifaceSeq.Add(1))
	host := ifname + "h"
	l.run("ip", "link", "add", ifname, "type", "veth", "peer", "name", host)
	l.run("ip", "link", "set", ifname, "netns", ns)
	l.run("ip", "link", "set", host, "master", brName)
	l.run("ip", "link", "set", host, "up")
	l.run("ip", "-n", ns, "addr", "add", cidr, "dev", ifname)
	l.run("ip", "-n", ns, "link", "set", ifname, "up")
	l.run("ip", "-n", ns, "link", "set", "lo", "up")
}

// startDaemon runs `ip netns exec <ns> wireguard-go -f <iface>` (UNIQUE iface name) with
// env, waits until its UAPI socket accepts a connection (a LIVE listener, not merely the
// path existing — a SIGKILLed prior daemon can leave a stale socket file), tracks the
// process + socket path for teardown, and returns the created iface name.
func (l *lab) startDaemon(ns string, env []string) string {
	l.t.Helper()
	iface := fmt.Sprintf("wgt%d", ifaceSeq.Add(1))
	cmd := exec.Command("ip", "netns", "exec", ns, wgBin(l.t), "-f", iface)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr // daemon logs go to test output
	if err := cmd.Start(); err != nil {
		l.t.Fatalf("start daemon %s/%s: %v", ns, iface, err)
	}
	l.procs = append(l.procs, cmd)
	sock := "/var/run/wireguard/" + iface + ".sock"
	l.socks = append(l.socks, sock)
	if !waitFor(5*time.Second, func() bool {
		c, err := net.Dial("unix", sock)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	}) {
		l.t.Fatalf("UAPI socket %s did not become live", sock)
	}
	return iface
}

// uapiSet writes a set= transaction to the daemon's UAPI socket and checks errno=0.
func (l *lab) uapiSet(iface, cfg string) {
	l.t.Helper()
	c, err := net.Dial("unix", "/var/run/wireguard/"+iface+".sock")
	if err != nil {
		l.t.Fatalf("dial uapi %s: %v", iface, err)
	}
	defer c.Close()
	if _, err := fmt.Fprintf(c, "set=1\n%s\n", cfg); err != nil {
		l.t.Fatalf("write uapi: %v", err)
	}
	buf := make([]byte, 256)
	n, _ := c.Read(buf)
	if !bytes.Contains(buf[:n], []byte("errno=0")) {
		l.t.Fatalf("uapi set %s failed: %s", iface, buf[:n])
	}
}

// ifup assigns the tunnel address and brings the wg interface up inside its namespace.
func (l *lab) ifup(ns, iface, cidr string) {
	l.run("ip", "-n", ns, "addr", "add", cidr, "dev", iface)
	l.run("ip", "-n", ns, "link", "set", iface, "up")
}

// ping runs ping inside ns and returns whether it succeeded.
func (l *lab) ping(ns, target string) bool {
	cmd := exec.Command("ip", "netns", "exec", ns, "ping", "-c", "3", "-W", "2", target)
	return cmd.Run() == nil
}

// startWstunnel runs the real wstunnel server binary in ns (plain ws), restricted to
// the wg UDP endpoint. extraArgs are inserted before the listen URL (e.g.
// --websocket-mask-frame). wstunnel is REQUIRED: a missing binary is a setup failure.
func (l *lab) startWstunnel(ns, listenURL, restrictTo string, extraArgs ...string) {
	l.t.Helper()
	bin := os.Getenv("WSTUNNEL_BIN")
	if bin == "" {
		// If the e2e runs at all (Linux+root, past requireRootLinux), wstunnel is REQUIRED —
		// a missing binary is a setup failure, never a reason to skip and hide the gap.
		l.t.Fatal("WSTUNNEL_BIN not set (the wstunnel e2e requires the real wstunnel binary)")
	}
	args := append([]string{"netns", "exec", ns, bin, "server", "--restrict-to", restrictTo}, extraArgs...)
	args = append(args, listenURL)
	cmd := exec.Command("ip", args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		l.t.Fatalf("start wstunnel: %v", err)
	}
	l.procs = append(l.procs, cmd)
	time.Sleep(500 * time.Millisecond) // let it bind
}

func (l *lab) cleanup() {
	for _, c := range l.procs {
		if c.Process != nil {
			_ = c.Process.Kill()
			_, _ = c.Process.Wait()
		}
	}
	for _, s := range l.socks {
		_ = os.Remove(s) // SIGKILL does not let the daemon remove its own UAPI socket
	}
	for _, ns := range l.ns {
		_ = exec.Command("ip", "netns", "del", ns).Run()
	}
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
