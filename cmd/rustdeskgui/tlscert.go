package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// ensureSelfSigned writes a self-signed certificate and key if they do not
// already exist, naming every host the browser might use. Serving HTTPS with a
// warning beats serving plaintext silently, and the pair persists in the data
// volume so the fingerprint stays stable across restarts rather than changing
// under the user every time.
//
// extraHosts matters more than it looks: the WebSocket to hbbs/hbbr is proxied
// through this same origin, and a browser will not prompt to accept a
// certificate for a WebSocket - it just fails. The certificate therefore has to
// cover the exact address typed into the address bar, so that one accepted
// exception covers the page and its sockets together.
func ensureSelfSigned(certFile, keyFile string, extraHosts ...string) error {
	if fileExists(certFile) && fileExists(keyFile) {
		if covers(certFile, extraHosts) {
			return nil
		}
		// Regenerate rather than serve a certificate that cannot be accepted
		// for this address.
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generating serial: %w", err)
	}

	host, _ := os.Hostname()
	if host == "" {
		host = "rustdeskgui"
	}

	dnsNames := []string{host, "localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, h := range extraHosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"rustdeskgui"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	if err := writePEM(certFile, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshalling key: %w", err)
	}
	return writePEM(keyFile, "EC PRIVATE KEY", keyDER, 0o600)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	return nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// covers reports whether an existing certificate already names every host, so a
// restart does not pointlessly invalidate an exception the user has accepted.
func covers(certFile string, hosts []string) bool {
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if cert.VerifyHostname(h) != nil {
			return false
		}
	}
	return true
}
