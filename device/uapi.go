/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/ipc"
)

type IPCError struct {
	code int64 // error code
	err  error // underlying/wrapped error
}

func (s IPCError) Error() string {
	return fmt.Sprintf("IPC error %d: %v", s.code, s.err)
}

func (s IPCError) Unwrap() error {
	return s.err
}

func (s IPCError) ErrorCode() int64 {
	return s.code
}

func ipcErrorf(code int64, msg string, args ...any) *IPCError {
	return &IPCError{code: code, err: fmt.Errorf(msg, args...)}
}

var byteBufferPool = &sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// These reporter interfaces let IpcGetOperation round-trip the WebSocket transport's
// additive keys without pulling transport specifics into the device core: only the
// WebSocket bind and its dialing endpoints implement them, so get=1 output for a
// plain UDP peer only gains the transport= line.
type wsListenReporter interface {
	WSListenURL() string
}

// wsServerReporter is implemented by the bind so IpcGet can round-trip the
// device-level WebSocket server/listener settings.
type wsServerReporter interface {
	WSServerTLSPaths() (cert, key string)
	WSServerBearer() string
	WSTrustedProxies() []netip.Prefix
}

// wsPeerReporter is implemented by a dialing *conn.WSEndpoint so IpcGet can
// round-trip the per-peer WebSocket keys.
type wsPeerReporter interface {
	WSPeerKVs() []string
}

// IpcGetOperation implements the WireGuard configuration protocol "get" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcGetOperation(w io.Writer) error {
	device.ipcMutex.RLock()
	defer device.ipcMutex.RUnlock()

	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer byteBufferPool.Put(buf)
	sendf := func(format string, args ...any) {
		fmt.Fprintf(buf, format, args...)
		buf.WriteByte('\n')
	}
	keyf := func(prefix string, key *[32]byte) {
		buf.Grow(len(key)*2 + 2 + len(prefix))
		buf.WriteString(prefix)
		buf.WriteByte('=')
		const hex = "0123456789abcdef"
		for i := 0; i < len(key); i++ {
			buf.WriteByte(hex[key[i]>>4])
			buf.WriteByte(hex[key[i]&0xf])
		}
		buf.WriteByte('\n')
	}

	func() {
		// lock required resources

		device.net.RLock()
		defer device.net.RUnlock()

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		device.peers.RLock()
		defer device.peers.RUnlock()

		// serialize device related values

		if !device.staticIdentity.privateKey.IsZero() {
			keyf("private_key", (*[32]byte)(&device.staticIdentity.privateKey))
		}

		if device.net.port != 0 {
			sendf("listen_port=%d", device.net.port)
		}

		if device.net.fwmark != 0 {
			sendf("fwmark=%d", device.net.fwmark)
		}

		if r, ok := device.net.bind.(wsListenReporter); ok {
			if url := r.WSListenURL(); url != "" {
				sendf("ws_listen=%s", url)
			}
		}

		if r, ok := device.net.bind.(wsServerReporter); ok {
			if cert, key := r.WSServerTLSPaths(); cert != "" && key != "" {
				sendf("ws_server_tls_cert=%s", cert)
				sendf("ws_server_tls_key=%s", key)
			}
			if bearer := r.WSServerBearer(); bearer != "" {
				sendf("ws_server_bearer=%s", bearer) // value emitted (like a key), never logged
			}
			for _, p := range r.WSTrustedProxies() {
				sendf("ws_trusted_proxies=%s", p.String())
			}
		}

		for _, peer := range device.peers.keyMap {
			// Serialize peer state.
			peer.handshake.mutex.RLock()
			keyf("public_key", (*[32]byte)(&peer.handshake.remoteStatic))
			keyf("preshared_key", (*[32]byte)(&peer.handshake.presharedKey))
			peer.handshake.mutex.RUnlock()
			sendf("protocol_version=1")
			transport := peer.transport
			if transport == "" {
				transport = peerTransportUDP
			}
			sendf("transport=%s", transport)
			peer.endpoint.Lock()
			if peer.endpoint.val != nil {
				sendf("endpoint=%s", peer.endpoint.val.DstToString())
				if wc, ok := peer.endpoint.val.(wsPeerReporter); ok {
					for _, kv := range wc.WSPeerKVs() {
						sendf("%s", kv)
					}
				}
			}
			peer.endpoint.Unlock()

			nano := peer.lastHandshakeNano.Load()
			secs := nano / time.Second.Nanoseconds()
			nano %= time.Second.Nanoseconds()

			sendf("last_handshake_time_sec=%d", secs)
			sendf("last_handshake_time_nsec=%d", nano)
			sendf("tx_bytes=%d", peer.txBytes.Load())
			sendf("rx_bytes=%d", peer.rxBytes.Load())
			sendf("persistent_keepalive_interval=%d", peer.persistentKeepaliveInterval.Load())

			device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
				sendf("allowed_ip=%s", prefix.String())
				return true
			})
		}
	}()

	// send lines (does not require resource locks)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to write output: %w", err)
	}

	return nil
}

// IpcSetOperation implements the WireGuard configuration protocol "set" operation.
// See https://www.wireguard.com/xplatform/#configuration-protocol for details.
func (device *Device) IpcSetOperation(r io.Reader) (err error) {
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	defer func() {
		if err != nil {
			device.log.Errorf("%v", err)
		}
	}()

	peer := new(ipcSetPeer)
	deviceConfig := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			// Blank line means terminate operation.
			return peer.handlePostConfig()
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ipcErrorf(ipc.IpcErrorProtocol, "failed to parse line %q", line)
		}

		if key == "public_key" {
			if deviceConfig {
				deviceConfig = false
			}
			if err := peer.handlePostConfig(); err != nil {
				return err
			}
			// Load/create the peer we are now configuring.
			err := device.handlePublicKeyLine(peer, value)
			if err != nil {
				return err
			}
			continue
		}

		var err error
		if deviceConfig {
			err = device.handleDeviceLine(key, value)
		} else {
			err = device.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return err
		}
	}
	if err := peer.handlePostConfig(); err != nil {
		return err
	}

	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil
}

func (device *Device) handleDeviceLine(key, value string) error {
	switch key {
	case "private_key":
		var sk NoisePrivateKey
		err := sk.FromMaybeZeroHex(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set private_key: %w", err)
		}
		device.log.Verbosef("UAPI: Updating private key")
		device.SetPrivateKey(sk)

	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to parse listen_port: %w", err)
		}

		// update port and rebind
		device.log.Verbosef("UAPI: Updating listen port")

		device.net.Lock()
		device.net.port = uint16(port)
		device.net.Unlock()

		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set listen_port: %w", err)
		}

	case "fwmark":
		mark, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid fwmark: %w", err)
		}

		device.log.Verbosef("UAPI: Updating fwmark")
		if err := device.BindSetMark(uint32(mark)); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to update fwmark: %w", err)
		}

	case "ws_listen":
		binder, ok := device.net.bind.(conn.WebSocketBinder)
		if !ok {
			return ipcErrorf(ipc.IpcErrorInvalid, "ws_listen requires the websocket transport")
		}
		device.log.Verbosef("UAPI: Updating websocket listen address")
		if err := binder.SetWSListen(value); err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set ws_listen: %w", err)
		}
		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set ws_listen: %w", err)
		}

	case "ws_server_tls_cert":
		binder, err := device.wsBinder()
		if err != nil {
			return err
		}
		binder.SetServerCertPath(value)
		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set ws_server_tls_cert: %w", err)
		}

	case "ws_server_tls_key":
		binder, err := device.wsBinder()
		if err != nil {
			return err
		}
		binder.SetServerKeyPath(value)
		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set ws_server_tls_key: %w", err)
		}

	case "ws_server_bearer":
		binder, err := device.wsBinder()
		if err != nil {
			return err
		}
		device.log.Verbosef("UAPI: Updating websocket server bearer") // key name only, never the value
		binder.SetServerBearer(value)
		// BindUpdate so a running listener (opened by an earlier ws_listen line in the
		// same setconf) reopens with the complete server config, regardless of key order.
		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set ws_server_bearer: %w", err)
		}

	case "ws_trusted_proxies":
		binder, err := device.wsBinder()
		if err != nil {
			return err
		}
		prefixes, err := parseCIDRList(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid ws_trusted_proxies: %w", err)
		}
		binder.SetTrustedProxies(prefixes)
		if err := device.BindUpdate(); err != nil {
			return ipcErrorf(ipc.IpcErrorPortInUse, "failed to set ws_trusted_proxies: %w", err)
		}

	case "replace_peers":
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set replace_peers, invalid value: %v", value)
		}
		device.log.Verbosef("UAPI: Removing all peers")
		device.RemoveAllPeers()

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI device key: %v", key)
	}

	return nil
}

// An ipcSetPeer is the current state of an IPC set operation on a peer.
type ipcSetPeer struct {
	*Peer        // Peer is the current peer being operated on
	dummy   bool // dummy reports whether this peer is a temporary, placeholder peer
	created bool // new reports whether this is a newly created peer
	pkaOn   bool // pkaOn reports whether the peer had the persistent keepalive turn on
	// Per-peer transport + endpoint + WebSocket keys, collected across lines and
	// consumed in handlePostConfig. Reset per peer in handlePublicKeyLine so peer N
	// never inherits peer N-1's values. `transport`/`endpointStr` shadow the promoted
	// Peer fields deliberately; use peer.Peer.transport / peer.endpoint for those.
	transport      string
	transportSeen  bool
	endpointStr    string
	endpointSeen   bool
	wsURL          string
	wstunnelTarget string
	wsBearer       string
	wsMask         bool
	wsTLSCA        string
	wsTLSCert      string
	wsTLSKey       string
	wsTLSInsecure  bool
	wsPingInterval time.Duration
	wsBackoffMin   time.Duration
	wsBackoffMax   time.Duration
	wsSeen         map[string]bool // presence of each ws_* key (bool/duration zero values are ambiguous)
}

func (peer *ipcSetPeer) handlePostConfig() error {
	if peer.Peer == nil || peer.dummy {
		return nil
	}
	// Effective transport: mandatory at creation; an incremental update may omit it
	// and keeps the peer's persisted transport (matches UDP incremental updates).
	if peer.transportSeen {
		t, err := parsePeerTransport(peer.transport)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid transport: %w", err)
		}
		peer.Peer.transport = t
	} else if peer.created {
		return ipcErrorf(ipc.IpcErrorInvalid, "peer missing mandatory transport")
	}

	switch peer.Peer.transport {
	case peerTransportUDP:
		if peer.anyWSKeySeen() {
			return ipcErrorf(ipc.IpcErrorInvalid, "ws_* keys are not allowed for transport=udp")
		}
		if peer.endpointSeen {
			ep, err := peer.device.net.bind.ParseEndpoint(peer.endpointStr)
			if err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to set endpoint %v: %w", peer.endpointStr, err)
			}
			peer.setEndpoint(ep)
		}
	case peerTransportWebSocket, peerTransportWstunnel:
		if peer.wsSeen["ws_url"] { // dialing peer
			if !peer.endpointSeen {
				return ipcErrorf(ipc.IpcErrorInvalid, "dialing websocket peer requires endpoint")
			}
			ap, err := netip.ParseAddrPort(peer.endpointStr)
			if err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "invalid endpoint %q: %w", peer.endpointStr, err)
			}
			binder, ok := peer.device.net.bind.(conn.WebSocketBinder)
			if !ok {
				return ipcErrorf(ipc.IpcErrorInvalid, "websocket transport not available")
			}
			// Transport from the persisted enum (survives an incremental update that
			// re-sends ws_url without transport=), not the raw ipcSetPeer.transport.
			ep, err := binder.ParseWSPeerEndpoint(conn.WSPeerConfig{
				Endpoint:       ap,
				Transport:      string(peer.Peer.transport),
				URL:            peer.wsURL,
				WstunnelTarget: peer.wstunnelTarget,
				Bearer:         peer.wsBearer,
				Mask:           peer.wsMask,
				TLSCAPath:      peer.wsTLSCA,
				TLSCertPath:    peer.wsTLSCert,
				TLSKeyPath:     peer.wsTLSKey,
				TLSInsecure:    peer.wsTLSInsecure,
				PingInterval:   peer.wsPingInterval,
				BackoffMin:     peer.wsBackoffMin,
				BackoffMax:     peer.wsBackoffMax,
			})
			if err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "failed to build websocket endpoint: %w", err)
			}
			peer.setEndpoint(ep)
		} else if peer.wsSeen["wstunnel_target"] { // inbound peer must not carry a dial target
			return ipcErrorf(ipc.IpcErrorInvalid, "wstunnel_target requires ws_url")
		}
	}

	if peer.created {
		peer.endpoint.disableRoaming = peer.device.net.brokenRoaming && peer.endpoint.val != nil
	}
	if peer.device.isUp() {
		peer.Start()
		if peer.pkaOn {
			peer.SendKeepalive()
		}
		peer.SendStagedPackets()
	}
	return nil
}

func (device *Device) handlePublicKeyLine(peer *ipcSetPeer, value string) error {
	// A new peer begins: clear the per-peer transport/endpoint/WebSocket keys so they
	// never leak from the previous peer (ipcSetPeer is allocated once and reused for
	// the whole op). The persisted Peer.transport is NOT reset here — an incremental
	// update of an existing peer keeps it.
	peer.transport = ""
	peer.transportSeen = false
	peer.endpointStr = ""
	peer.endpointSeen = false
	peer.wsURL = ""
	peer.wstunnelTarget = ""
	peer.wsBearer = ""
	peer.wsMask = false
	peer.wsTLSCA = ""
	peer.wsTLSCert = ""
	peer.wsTLSKey = ""
	peer.wsTLSInsecure = false
	peer.wsPingInterval = 0
	peer.wsBackoffMin = 0
	peer.wsBackoffMax = 0
	peer.wsSeen = nil

	// Load/create the peer we are configuring.
	var publicKey NoisePublicKey
	err := publicKey.FromHex(value)
	if err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "failed to get peer by public key: %w", err)
	}

	// Ignore peer with the same public key as this device.
	device.staticIdentity.RLock()
	peer.dummy = device.staticIdentity.publicKey.Equals(publicKey)
	device.staticIdentity.RUnlock()

	if peer.dummy {
		peer.Peer = &Peer{}
	} else {
		peer.Peer = device.LookupPeer(publicKey)
	}

	peer.created = peer.Peer == nil
	if peer.created {
		peer.Peer, err = device.NewPeer(publicKey)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to create new peer: %w", err)
		}
		device.log.Verbosef("%v - UAPI: Created", peer.Peer)
	}
	return nil
}

func (device *Device) handlePeerLine(peer *ipcSetPeer, key, value string) error {
	switch key {
	case "update_only":
		// allow disabling of creation
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set update only, invalid value: %v", value)
		}
		if peer.created && !peer.dummy {
			device.RemovePeer(peer.handshake.remoteStatic)
			peer.Peer = &Peer{}
			peer.dummy = true
		}

	case "remove":
		// remove currently selected peer from device
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set remove, invalid value: %v", value)
		}
		if !peer.dummy {
			device.log.Verbosef("%v - UAPI: Removing", peer.Peer)
			device.RemovePeer(peer.handshake.remoteStatic)
		}
		peer.Peer = &Peer{}
		peer.dummy = true

	case "preshared_key":
		device.log.Verbosef("%v - UAPI: Updating preshared key", peer.Peer)

		peer.handshake.mutex.Lock()
		err := peer.handshake.presharedKey.FromHex(value)
		peer.handshake.mutex.Unlock()

		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set preshared key: %w", err)
		}

	case "transport":
		switch value {
		case "udp", "websocket", "wstunnel":
			peer.transport = value
			peer.transportSeen = true
		default:
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid transport %q (want udp|websocket|wstunnel)", value)
		}

	case "endpoint":
		device.log.Verbosef("%v - UAPI: Updating endpoint", peer.Peer)
		// Deferred: the endpoint TYPE depends on transport + ws_url, resolved in
		// handlePostConfig, so key order is irrelevant.
		peer.endpointStr = value
		peer.endpointSeen = true

	case "ws_url":
		peer.markWS(key)
		peer.wsURL = value

	case "wstunnel_target":
		peer.markWS(key)
		peer.wstunnelTarget = value

	case "ws_bearer":
		peer.markWS(key)
		// Secret: log the key name only, never the value.
		device.log.Verbosef("%v - UAPI: Updating websocket bearer", peer.Peer)
		peer.wsBearer = value

	case "ws_mask":
		peer.markWS(key)
		peer.wsMask = value == "true"

	case "ws_tls_ca":
		peer.markWS(key)
		peer.wsTLSCA = value

	case "ws_tls_cert":
		peer.markWS(key)
		peer.wsTLSCert = value

	case "ws_tls_key":
		peer.markWS(key)
		peer.wsTLSKey = value

	case "ws_tls_insecure":
		peer.markWS(key)
		peer.wsTLSInsecure = value == "true"

	case "ws_ping_interval":
		peer.markWS(key)
		d, err := parseMillis(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid ws_ping_interval: %w", err)
		}
		peer.wsPingInterval = d

	case "ws_backoff_min":
		peer.markWS(key)
		d, err := parseMillis(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid ws_backoff_min: %w", err)
		}
		peer.wsBackoffMin = d

	case "ws_backoff_max":
		peer.markWS(key)
		d, err := parseMillis(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid ws_backoff_max: %w", err)
		}
		peer.wsBackoffMax = d

	case "persistent_keepalive_interval":
		device.log.Verbosef("%v - UAPI: Updating persistent keepalive interval", peer.Peer)

		secs, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set persistent keepalive interval: %w", err)
		}

		old := peer.persistentKeepaliveInterval.Swap(uint32(secs))

		// Send immediate keepalive if we're turning it on and before it wasn't on.
		peer.pkaOn = old == 0 && secs != 0

	case "replace_allowed_ips":
		device.log.Verbosef("%v - UAPI: Removing all allowedips", peer.Peer)
		if value != "true" {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to replace allowedips, invalid value: %v", value)
		}
		if peer.dummy {
			return nil
		}
		device.allowedips.RemoveByPeer(peer.Peer)

	case "allowed_ip":
		add := true
		verb := "Adding"
		if len(value) > 0 && value[0] == '-' {
			add = false
			verb = "Removing"
			value = value[1:]
		}
		device.log.Verbosef("%v - UAPI: %s allowedip", peer.Peer, verb)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ipcErrorf(ipc.IpcErrorInvalid, "failed to set allowed ip: %w", err)
		}
		if peer.dummy {
			return nil
		}
		if add {
			device.allowedips.Insert(prefix, peer.Peer)
		} else {
			device.allowedips.Remove(prefix, peer.Peer)
		}

	case "protocol_version":
		if value != "1" {
			return ipcErrorf(ipc.IpcErrorInvalid, "invalid protocol version: %v", value)
		}

	default:
		return ipcErrorf(ipc.IpcErrorInvalid, "invalid UAPI peer key: %v", key)
	}

	return nil
}

// parsePeerTransport maps the UAPI transport value to the persisted enum. It is the
// exact inverse of peerTransport's string values.
func parsePeerTransport(s string) (peerTransport, error) {
	switch s {
	case "udp":
		return peerTransportUDP, nil
	case "websocket":
		return peerTransportWebSocket, nil
	case "wstunnel":
		return peerTransportWstunnel, nil
	default:
		return "", fmt.Errorf("want udp|websocket|wstunnel, got %q", s)
	}
}

// markWS records the presence of a ws_* key so handlePostConfig can reject any of
// them under transport=udp (bool/duration zero values are ambiguous).
func (peer *ipcSetPeer) markWS(key string) {
	if peer.wsSeen == nil {
		peer.wsSeen = make(map[string]bool)
	}
	peer.wsSeen[key] = true
}

func (peer *ipcSetPeer) anyWSKeySeen() bool { return len(peer.wsSeen) > 0 }

// setEndpoint installs the resolved endpoint on the peer under its lock.
func (peer *ipcSetPeer) setEndpoint(ep conn.Endpoint) {
	peer.endpoint.Lock()
	peer.endpoint.val = ep
	peer.endpoint.Unlock()
}

// wsBinder returns the WebSocket binder, or an error if the bind is not
// WebSocket-capable.
func (device *Device) wsBinder() (conn.WebSocketBinder, error) {
	b, ok := device.net.bind.(conn.WebSocketBinder)
	if !ok {
		return nil, ipcErrorf(ipc.IpcErrorInvalid, "requires the websocket transport")
	}
	return b, nil
}

// parseMillis parses a non-negative integer number of milliseconds into a Duration.
func parseMillis(value string) (time.Duration, error) {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("must be >= 0")
	}
	return time.Duration(n) * time.Millisecond, nil
}

// parseCIDRList parses a comma-separated list of CIDR prefixes.
func parseCIDRList(value string) ([]netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, p := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func (device *Device) IpcGet() (string, error) {
	buf := new(strings.Builder)
	if err := device.IpcGetOperation(buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (device *Device) IpcSet(uapiConf string) error {
	return device.IpcSetOperation(strings.NewReader(uapiConf))
}

func (device *Device) IpcHandle(socket net.Conn) {
	defer socket.Close()

	buffered := func(s io.ReadWriter) *bufio.ReadWriter {
		reader := bufio.NewReader(s)
		writer := bufio.NewWriter(s)
		return bufio.NewReadWriter(reader, writer)
	}(socket)

	for {
		op, err := buffered.ReadString('\n')
		if err != nil {
			return
		}

		// handle operation
		switch op {
		case "set=1\n":
			err = device.IpcSetOperation(buffered.Reader)
		case "get=1\n":
			var nextByte byte
			nextByte, err = buffered.ReadByte()
			if err != nil {
				return
			}
			if nextByte != '\n' {
				err = ipcErrorf(ipc.IpcErrorInvalid, "trailing character in UAPI get: %q", nextByte)
				break
			}
			err = device.IpcGetOperation(buffered.Writer)
		default:
			device.log.Errorf("invalid UAPI operation: %v", op)
			return
		}

		// write status
		var status *IPCError
		if err != nil && !errors.As(err, &status) {
			// shouldn't happen
			status = ipcErrorf(ipc.IpcErrorUnknown, "other UAPI error: %w", err)
		}
		if status != nil {
			device.log.Errorf("%v", status)
			fmt.Fprintf(buffered, "errno=%d\n\n", status.ErrorCode())
		} else {
			fmt.Fprintf(buffered, "errno=0\n\n")
		}
		buffered.Flush()
	}
}
