package mitm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/igoogolx/itun2socks/internal/configuration"
)

const (
	caCertFile = "mitm_ca.crt"
	caKeyFile  = "mitm_ca_key.enc"
)

// CA holds the Root CA certificate and key, plus an in-memory leaf cert cache.
type CA struct {
	cert      *x509.Certificate
	key       crypto.PrivateKey
	certPEM   []byte
	leafCache map[string]*tls.Certificate
	cacheMu   sync.RWMutex
}

// Init loads an existing Root CA from configDir, or generates a new one if absent.
func Init(configDir string) (*CA, error) {
	certPath := filepath.Join(configDir, caCertFile)
	keyPath := filepath.Join(configDir, caKeyFile)

	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	if certExists && keyExists {
		return loadCA(certPath, keyPath)
	}
	return generateCA(configDir, certPath, keyPath)
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

func loadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("mitm: read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("mitm: invalid CA cert PEM in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse CA cert: %w", err)
	}

	encData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("mitm: read CA key: %w", err)
	}
	decrypted := configuration.DecryptData(strings.TrimSpace(string(encData)))
	keyBlock, _ := pem.Decode([]byte(decrypted))
	if keyBlock == nil {
		return nil, fmt.Errorf("mitm: invalid CA private key PEM (decryption may have failed)")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		rsaKey, err2 := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("mitm: parse CA private key: %w (PKCS8: %v)", err2, err)
		}
		key = rsaKey
	}

	return &CA{
		cert:      cert,
		key:       key,
		certPEM:   certPEM,
		leafCache: make(map[string]*tls.Certificate),
	}, nil
}

func generateCA(configDir, certPath, keyPath string) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("mitm: generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("mitm: generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "Lux SSL Inspection CA",
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("mitm: create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse generated CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("mitm: marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	encrypted := configuration.EncryptData(string(keyPEM))

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("mitm: create config dir: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("mitm: write CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(encrypted), 0600); err != nil {
		return nil, fmt.Errorf("mitm: write CA key: %w", err)
	}

	return &CA{
		cert:      cert,
		key:       key,
		certPEM:   certPEM,
		leafCache: make(map[string]*tls.Certificate),
	}, nil
}

// TLSConfig returns a *tls.Config with GetCertificate set to serve per-domain leaf certs.
// MinVersion is set to TLS 1.0 so we can intercept legacy clients.
func (ca *CA) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10, // accept legacy TLS 1.0/1.1 clients
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			domain := hello.ServerName
			if domain == "" {
				return nil, fmt.Errorf("mitm: no SNI in ClientHello")
			}
			return ca.GetOrCreateLeafCert(domain)
		},
	}
}

// GetOrCreateLeafCert returns a cached leaf cert for domain, generating one if absent or expired.
func (ca *CA) GetOrCreateLeafCert(domain string) (*tls.Certificate, error) {
	ca.cacheMu.RLock()
	if cert, ok := ca.leafCache[domain]; ok {
		if time.Now().Before(cert.Leaf.NotAfter) {
			ca.cacheMu.RUnlock()
			return cert, nil
		}
	}
	ca.cacheMu.RUnlock()

	cert, err := ca.generateLeafCert(domain)
	if err != nil {
		return nil, err
	}

	ca.cacheMu.Lock()
	ca.leafCache[domain] = cert
	ca.evictExpiredLocked()
	ca.cacheMu.Unlock()

	return cert, nil
}

func (ca *CA) generateLeafCert(domain string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("mitm: generate leaf key for %s: %w", domain, err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("mitm: generate leaf serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("mitm: create leaf cert for %s: %w", domain, err)
	}

	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse leaf cert: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func (ca *CA) evictExpiredLocked() {
	now := time.Now()
	for domain, cert := range ca.leafCache {
		if now.After(cert.Leaf.NotAfter) {
			delete(ca.leafCache, domain)
		}
	}
}

// CertPEM returns the Root CA certificate in PEM format.
func (ca *CA) CertPEM() []byte { return ca.certPEM }

// CertDER returns the Root CA certificate in DER (ASN.1) format.
func (ca *CA) CertDER() []byte { return ca.cert.Raw }

// Fingerprint returns the SHA-256 fingerprint as a colon-separated uppercase hex string.
func (ca *CA) Fingerprint() string {
	sum := sha256.Sum256(ca.cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// GeneratedAt returns the NotBefore time of the Root CA certificate.
func (ca *CA) GeneratedAt() time.Time { return ca.cert.NotBefore }
