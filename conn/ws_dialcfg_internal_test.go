/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeClientCertKey generates a throwaway ECDSA self-signed certificate and its key,
// writes them to temp PEM files, and returns their paths — for exercising the mTLS
// (ws_tls_cert / ws_tls_key) branch of buildDialConfig.
func writeClientCertKey(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ws-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// TestBuildDialConfig_MTLS verifies that a wss:// endpoint carrying ws_tls_cert/ws_tls_key
// loads the client keypair into the dial TLS config (mutual TLS) and derives the SNI from
// the ws_url host.
func TestBuildDialConfig_MTLS(t *testing.T) {
	certPath, keyPath := writeClientCertKey(t)
	e := &WSEndpoint{
		wsURL:       "wss://example.com:443/wg",
		dialect:     wsDialectStandard,
		tlsCertPath: certPath,
		tlsKeyPath:  keyPath,
	}
	dc, err := buildDialConfig(e)
	if err != nil {
		t.Fatalf("buildDialConfig: %v", err)
	}
	if dc.tls == nil {
		t.Fatal("tls config is nil for a wss:// endpoint")
	}
	if len(dc.tls.Certificates) != 1 {
		t.Errorf("client certificates = %d, want 1 (mTLS)", len(dc.tls.Certificates))
	}
	if dc.tls.ServerName != "example.com" {
		t.Errorf("SNI = %q, want example.com", dc.tls.ServerName)
	}
}

// TestBuildDialConfig_MTLSBadPath verifies that missing mTLS material is a hard error,
// not a silent fallback to no client certificate.
func TestBuildDialConfig_MTLSBadPath(t *testing.T) {
	e := &WSEndpoint{
		wsURL:       "wss://example.com:443/wg",
		dialect:     wsDialectStandard,
		tlsCertPath: filepath.Join(t.TempDir(), "missing.pem"),
		tlsKeyPath:  filepath.Join(t.TempDir(), "missing.key"),
	}
	if _, err := buildDialConfig(e); err == nil {
		t.Error("buildDialConfig accepted missing mTLS cert/key files")
	}
}
