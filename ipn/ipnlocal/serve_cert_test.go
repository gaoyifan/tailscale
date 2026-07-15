// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package ipnlocal

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/tstest/tlstest"
)

func writeManualCertPair(t *testing.T, certFile, keyFile string, domain tlstest.Domain) {
	t.Helper()
	if err := os.WriteFile(certFile, domain.CertPEM(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, domain.KeyPEM(), 0600); err != nil {
		t.Fatal(err)
	}
}

func manualCertDomain(t *testing.T, cert *tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.DNSNames[0]
}

func TestManualServeCertificateReload(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	first := tlstest.Domain("first.example")
	second := tlstest.Domain("second.example")

	b := new(LocalBackend)
	get := func() *tls.Certificate {
		t.Helper()
		cert, err := b.getManualServeCertificate(certFile, keyFile)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}

	if _, err := b.getManualServeCertificate(certFile, keyFile); err == nil {
		t.Fatal("missing certificate files unexpectedly succeeded")
	}
	if err := os.WriteFile(certFile, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.getManualServeCertificate(certFile, keyFile); err == nil {
		t.Fatal("invalid initial certificate unexpectedly succeeded")
	}

	writeManualCertPair(t, certFile, keyFile, first)
	if got := manualCertDomain(t, get()); got != string(first) {
		t.Fatalf("initial certificate domain = %q, want %q", got, first)
	}

	// A common renewal updates the certificate and key as two separate file
	// operations. Keep serving the old pair while only one file is new.
	var logs []string
	b.logf = func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	if err := os.WriteFile(certFile, second.CertPEM(), 0600); err != nil {
		t.Fatal(err)
	}
	if got := manualCertDomain(t, get()); got != string(first) {
		t.Fatalf("certificate during mismatched update = %q, want %q", got, first)
	}
	get()
	if len(logs) != 1 || !strings.Contains(logs[0], "reload failed") {
		t.Fatalf("logs after repeated failed reload = %q, want one failure", logs)
	}
	if err := os.WriteFile(keyFile, second.KeyPEM(), 0600); err != nil {
		t.Fatal(err)
	}
	if got := manualCertDomain(t, get()); got != string(second) {
		t.Fatalf("reloaded certificate domain = %q, want %q", got, second)
	}
	if len(logs) != 2 || !strings.Contains(logs[1], "reloaded") {
		t.Fatalf("logs after successful reload = %q, want failure and recovery", logs)
	}
	b.logf = nil

	if err := os.WriteFile(certFile, []byte("invalid certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("invalid key"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := manualCertDomain(t, get()); got != string(second) {
		t.Fatalf("certificate after invalid update = %q, want %q", got, second)
	}
	if err := os.Remove(certFile); err != nil {
		t.Fatal(err)
	}
	if got := manualCertDomain(t, get()); got != string(second) {
		t.Fatalf("certificate while file is absent = %q, want %q", got, second)
	}

	// Recovery from an invalid or missing update does not require a config
	// change or daemon restart.
	writeManualCertPair(t, certFile, keyFile, first)
	if got := manualCertDomain(t, get()); got != string(first) {
		t.Fatalf("certificate after recovery = %q, want %q", got, first)
	}

	// Atomic replacements are detected as well. The first rename temporarily
	// creates a mismatched pair and must not interrupt handshakes.
	newCert := filepath.Join(dir, "cert.pem.new")
	newKey := filepath.Join(dir, "key.pem.new")
	writeManualCertPair(t, newCert, newKey, second)
	if err := os.Rename(newCert, certFile); err != nil {
		t.Fatal(err)
	}
	if got := manualCertDomain(t, get()); got != string(first) {
		t.Fatalf("certificate between atomic replacements = %q, want %q", got, first)
	}
	if err := os.Rename(newKey, keyFile); err != nil {
		t.Fatal(err)
	}
	if got := manualCertDomain(t, get()); got != string(second) {
		t.Fatalf("certificate after atomic replacement = %q, want %q", got, second)
	}

	// A config change to different paths must not fall back to the certificate
	// cached for the previous paths.
	if _, err := b.getManualServeCertificate(filepath.Join(dir, "missing-cert.pem"), filepath.Join(dir, "missing-key.pem")); err == nil {
		t.Fatal("missing certificate at new paths unexpectedly used the previous certificate")
	}
}

func TestValidateServeManualCertificates(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	domain := tlstest.Domain("manual.example")
	writeManualCertPair(t, certFile, keyFile, domain)

	tests := []struct {
		name    string
		handler *ipn.TCPPortHandler
		wantErr bool
	}{
		{name: "none", handler: &ipn.TCPPortHandler{HTTPS: true}},
		{name: "valid HTTPS", handler: &ipn.TCPPortHandler{HTTPS: true, CertFile: certFile, KeyFile: keyFile}},
		{name: "valid TLS-terminated TCP", handler: &ipn.TCPPortHandler{TCPForward: "127.0.0.1:80", TerminateTLS: "node.test.ts.net", CertFile: certFile, KeyFile: keyFile}},
		{name: "certificate only", handler: &ipn.TCPPortHandler{HTTPS: true, CertFile: certFile}, wantErr: true},
		{name: "key only", handler: &ipn.TCPPortHandler{HTTPS: true, KeyFile: keyFile}, wantErr: true},
		{name: "relative paths", handler: &ipn.TCPPortHandler{HTTPS: true, CertFile: "cert.pem", KeyFile: "key.pem"}, wantErr: true},
		{name: "plain HTTP", handler: &ipn.TCPPortHandler{HTTP: true, CertFile: certFile, KeyFile: keyFile}, wantErr: true},
		{name: "raw TCP", handler: &ipn.TCPPortHandler{TCPForward: "127.0.0.1:80", CertFile: certFile, KeyFile: keyFile}, wantErr: true},
		{name: "mismatched pair", handler: &ipn.TCPPortHandler{HTTPS: true, CertFile: certFile, KeyFile: filepath.Join(dir, "missing-key.pem")}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServeManualCertificates(&ipn.ServeConfig{TCP: map[uint16]*ipn.TCPPortHandler{443: tt.handler}})
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateServeManualCertificates error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	same := &ipn.ServeConfig{TCP: map[uint16]*ipn.TCPPortHandler{
		443:  {HTTPS: true, CertFile: certFile, KeyFile: keyFile},
		8443: {HTTPS: true, CertFile: certFile, KeyFile: keyFile},
	}}
	if err := validateServeManualCertificates(same); err != nil {
		t.Fatalf("same certificate on multiple listeners: %v", err)
	}
	otherCert := filepath.Join(dir, "other-cert.pem")
	otherKey := filepath.Join(dir, "other-key.pem")
	writeManualCertPair(t, otherCert, otherKey, tlstest.Domain("other.example"))
	same.TCP[8443].CertFile = otherCert
	same.TCP[8443].KeyFile = otherKey
	if err := validateServeManualCertificates(same); err == nil {
		t.Fatal("different certificates on multiple listeners unexpectedly succeeded")
	}
}

func TestManualServeCertificateRoutesCustomSNIByPort(t *testing.T) {
	b := &LocalBackend{serveConfig: (&ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true, CertFile: "/cert.pem", KeyFile: "/key.pem"}},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"node.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Text: "ok"}}},
		},
	}).View()}
	req := httptest.NewRequest("GET", "https://custom.example/", nil)
	req.TLS = &tls.ConnectionState{ServerName: "custom.example"}
	ctx := serveHTTPContextKey.WithValue(req.Context(), &serveHTTPContext{DestPort: 443, ManualCert: true})
	req = req.WithContext(ctx)

	h, _, ok := b.getServeHandler(req)
	if !ok || h.Text() != "ok" {
		t.Fatalf("custom SNI handler = (%v, %v), want text handler", h, ok)
	}

	ctx = serveHTTPContextKey.WithValue(req.Context(), &serveHTTPContext{DestPort: 443})
	req = req.WithContext(ctx)
	if _, _, ok := b.getServeHandler(req); ok {
		t.Fatal("custom SNI unexpectedly routed without a manual certificate")
	}

	b.serveConfig = (&ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true, CertFile: "/cert.pem", KeyFile: "/key.pem"}},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{
			"one.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Text: "one"}}},
			"two.test.ts.net:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Text: "two"}}},
		},
	}).View()
	ctx = serveHTTPContextKey.WithValue(req.Context(), &serveHTTPContext{DestPort: 443, ManualCert: true})
	req = req.WithContext(ctx)
	if _, _, ok := b.getServeHandler(req); ok {
		t.Fatal("ambiguous web configs on one manual-certificate port unexpectedly routed")
	}
}

func TestManualServeCertificateIgnoresSNI(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	domain := tlstest.Domain("manual.example")
	writeManualCertPair(t, certFile, keyFile, domain)
	b := new(LocalBackend)
	getCert := b.getTLSServeCertForPort(443, "", certFile, keyFile)
	cert, err := getCert(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := manualCertDomain(t, cert); got != string(domain) {
		t.Fatalf("GetCertificate domain = %q, want %q", got, domain)
	}
}

func TestManualServeCertificateTLSHandshakeReload(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	first := tlstest.Domain("first.example")
	second := tlstest.Domain("second.example")

	b := new(LocalBackend)
	serverConfig := &tls.Config{GetCertificate: b.getTLSServeCertForPort(443, "", certFile, keyFile)}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(tlstest.TestRootCA()) {
		t.Fatal("failed to add test root CA")
	}
	handshake := func(domain tlstest.Domain) {
		t.Helper()
		serverConn, clientConn := net.Pipe()
		server := tls.Server(serverConn, serverConfig)
		client := tls.Client(clientConn, &tls.Config{RootCAs: roots, ServerName: string(domain)})
		serverErr := make(chan error, 1)
		go func() { serverErr <- server.Handshake() }()
		if err := client.Handshake(); err != nil {
			server.Close()
			client.Close()
			t.Fatal(err)
		}
		if err := <-serverErr; err != nil {
			t.Fatal(err)
		}
		peer := client.ConnectionState().PeerCertificates[0]
		if got := peer.DNSNames[0]; got != string(domain) {
			t.Fatalf("peer certificate domain = %q, want %q", got, domain)
		}
		server.Close()
		client.Close()
	}

	writeManualCertPair(t, certFile, keyFile, first)
	handshake(first)
	writeManualCertPair(t, certFile, keyFile, second)
	handshake(second)
}
