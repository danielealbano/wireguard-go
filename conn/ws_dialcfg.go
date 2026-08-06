/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
)

// dialConfig is the per-endpoint dial parameters derived from ws_url + the TLS
// paths. The actual TCP connect goes to WSEndpoint.dialTarget (the dialer's
// NetDial override); ws_url supplies only the TLS SNI / HTTP Host / upgrade path.
type dialConfig struct {
	dialURL   string      // ws_url with the wstunnel /<prefix>/events path applied when needed
	tls       *tls.Config // built from tlsCAPath/tlsCertPath/tlsKeyPath/tlsInsecure; nil for ws://
	subprotos []string
	header    http.Header
}

// dialConfig builds (once, cached) the dial parameters for e. Endpoints are
// immutable after set, so the config is computed lazily on first dial.
func (e *WSEndpoint) dialConfig() (*dialConfig, error) {
	e.dcOnce.Do(func() { e.dc, e.dcErr = buildDialConfig(e) })
	return e.dc, e.dcErr
}

func buildDialConfig(e *WSEndpoint) (*dialConfig, error) {
	dialURL, header, subprotos, err := wsUpgradeRequest(e)
	if err != nil {
		return nil, err
	}
	dc := &dialConfig{dialURL: dialURL, header: header, subprotos: subprotos}
	u, err := url.Parse(e.wsURL)
	if err != nil {
		return nil, fmt.Errorf("ws_url %q: %w", e.wsURL, err)
	}
	if u.Scheme == "wss" {
		t := &tls.Config{ServerName: hostnameOnly(u.Host), InsecureSkipVerify: e.tlsInsecure}
		if e.tlsCAPath != "" {
			pem, err := os.ReadFile(e.tlsCAPath)
			if err != nil {
				return nil, fmt.Errorf("ws_tls_ca %q: %w", e.tlsCAPath, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("ws_tls_ca %q: no certificates parsed", e.tlsCAPath)
			}
			t.RootCAs = pool
		}
		if e.tlsCertPath != "" || e.tlsKeyPath != "" {
			cert, err := tls.LoadX509KeyPair(e.tlsCertPath, e.tlsKeyPath)
			if err != nil {
				return nil, fmt.Errorf("ws mTLS cert/key: %w", err)
			}
			t.Certificates = []tls.Certificate{cert}
		}
		dc.tls = t
	}
	return dc, nil
}

// hostnameOnly returns host without the port, for TLS SNI.
func hostnameOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
