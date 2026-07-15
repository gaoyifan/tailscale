// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package ipnlocal

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"path/filepath"
	"sync"

	"tailscale.com/ipn"
	"tailscale.com/types/logger"
)

type manualServeCertPaths struct {
	certFile string
	keyFile  string
}

type manualServeCertificate struct {
	mu sync.Mutex

	paths   manualServeCertPaths
	cert    *tls.Certificate
	lastErr string
}

// get reads the certificate files on every handshake so both in-place writes
// and atomic replacements take effect immediately. If an update is temporarily
// invalid, it keeps serving the last valid certificate for the same paths.
func (c *manualServeCertificate) get(certFile, keyFile string, logf logger.Logf) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	paths := manualServeCertPaths{certFile: certFile, keyFile: keyFile}
	if paths != c.paths {
		c.paths = paths
		c.cert = nil
		c.lastErr = ""
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		err = fmt.Errorf("loading manual TLS certificate: %w", err)
		if msg := err.Error(); msg != c.lastErr {
			c.lastErr = msg
			if logf != nil {
				logf("serve: manual TLS certificate reload failed: %v", err)
			}
		}
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	changed := c.cert != nil && !bytes.Equal(c.cert.Certificate[0], pair.Certificate[0])
	recovered := c.lastErr != ""
	c.cert = &pair
	c.lastErr = ""
	if logf != nil && (changed || recovered) {
		logf("serve: reloaded manual TLS certificate")
	}
	return c.cert, nil
}

func (b *LocalBackend) getManualServeCertificate(certFile, keyFile string) (*tls.Certificate, error) {
	return b.serveManualCert.get(certFile, keyFile, b.logf)
}

func validateServeManualCertificates(sc *ipn.ServeConfig) error {
	var paths manualServeCertPaths
	return validateServeManualCertificatesAt("serve config", sc, &paths)
}

func validateServeManualCertificatesAt(name string, sc *ipn.ServeConfig, paths *manualServeCertPaths) error {
	if sc == nil {
		return nil
	}
	for port, h := range sc.TCP {
		if err := validateServeManualCertificate(h, paths); err != nil {
			return fmt.Errorf("%s TCP port %d: %w", name, port, err)
		}
	}
	for svcName, svc := range sc.Services {
		if svc == nil {
			continue
		}
		for port, h := range svc.TCP {
			if err := validateServeManualCertificate(h, paths); err != nil {
				return fmt.Errorf("service %s TCP port %d: %w", svcName, port, err)
			}
		}
	}
	for sessionID, fg := range sc.Foreground {
		if err := validateServeManualCertificatesAt("foreground session "+sessionID, fg, paths); err != nil {
			return err
		}
	}
	return nil
}

func validateServeManualCertificate(h *ipn.TCPPortHandler, paths *manualServeCertPaths) error {
	if h == nil || (h.CertFile == "" && h.KeyFile == "") {
		return nil
	}
	if h.CertFile == "" || h.KeyFile == "" {
		return fmt.Errorf("CertFile and KeyFile must both be set")
	}
	if !h.HTTPS && h.TerminateTLS == "" {
		return fmt.Errorf("manual certificates require HTTPS or TLS-terminated TCP")
	}
	if !filepath.IsAbs(h.CertFile) || !filepath.IsAbs(h.KeyFile) {
		return fmt.Errorf("CertFile and KeyFile must be absolute paths")
	}
	got := manualServeCertPaths{certFile: h.CertFile, keyFile: h.KeyFile}
	if *paths != (manualServeCertPaths{}) {
		if *paths != got {
			return fmt.Errorf("all manual TLS listeners must use the same CertFile and KeyFile")
		}
		return nil
	}
	if _, err := tls.LoadX509KeyPair(h.CertFile, h.KeyFile); err != nil {
		return fmt.Errorf("loading manual TLS certificate: %w", err)
	}
	*paths = got
	return nil
}
