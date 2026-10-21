// Package mitm terminates TLS for the forward entry so it can read HTTP status
// codes.
//
// A SOCKS5 CONNECT only carries bytes, so the proxy never learns whether the
// upstream answered 200 or 403. That makes the forward entry blind to exactly
// the signal the whole service exists to act on. Terminating TLS is the only
// way to see it: the proxy presents a certificate for the upstream host, reads
// the request in the clear, then opens its own TLS connection upstream.
//
// The cost is trust: the client must accept the certificate this package signs.
// That is a deployment decision, so the feature is opt-in and the CA is
// generated once and persisted.
package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA signs per-host certificates on demand.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	caPEM   []byte
	leafPEM []byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadOrCreate reads a CA from dir, generating one on first use.
//
// The CA is persisted because rotating it would invalidate every client's trust
// store: a restart must not silently break every caller.
func LoadOrCreate(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create ca dir: %w", err)
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if certPEM, err := os.ReadFile(certPath); err == nil {
		if keyPEM, err := os.ReadFile(keyPath); err == nil {
			ca, err := parse(certPEM, keyPEM)
			if err == nil {
				return ca, nil
			}
			// A corrupt CA is fatal rather than silently regenerated: replacing
			// it would break every client that trusts the old one.
			return nil, fmt.Errorf("parse existing ca: %w", err)
		}
	}

	ca, err := generate()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, ca.caPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write ca cert: %w", err)
	}
	if err := os.WriteFile(keyPath, ca.leafPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write ca key: %w", err)
	}
	return ca, nil
}

func generate() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "egress-filter local CA",
			Organization: []string{"egress-filter"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		key:     key,
		caPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leafPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

func parse(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("ca cert is not pem")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("ca key is not pem")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		key:     key,
		caPEM:   certPEM,
		leafPEM: keyPEM,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

// CertPEM returns the CA certificate clients must trust.
func (c *CA) CertPEM() []byte { return c.caPEM }

// Leaf returns a certificate for host, signing and caching it on first use.
//
// Hosts are cached because the handshake path is hot and signing costs a
// signature operation; without the cache every connection would pay it.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	if cert, ok := c.cache[host]; ok {
		c.mu.Unlock()
		return cert, nil
	}
	c.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// Both forms are set: a client may connect by name or by address, and a
	// mismatch surfaces as an opaque handshake error.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
	}

	c.mu.Lock()
	c.cache[host] = cert
	c.mu.Unlock()
	return cert, nil
}
