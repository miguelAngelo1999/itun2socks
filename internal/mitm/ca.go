package mitm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

// crlDPBase is the base URL for CRL Distribution Points in leaf certs.
// Port is set at runtime via SetCRLPort.
var crlDPBase = "http://127.0.0.1:1090"

// SetCRLPort sets the local port used for CRL Distribution Points and OCSP URIs
// in generated leaf certificates. Call this once on startup with the API server port.
// The CRL endpoint is served at http://127.0.0.1:<port>/crl.der (no auth required).
func SetCRLPort(port int) {
	crlDPBase = fmt.Sprintf("http://127.0.0.1:%d", port)
}

// CA holds the Root CA certificate and key, plus an in-memory leaf cert cache.
type CA struct {
	cert      *x509.Certificate
	key       crypto.PrivateKey
	certPEM   []byte
	leafCache map[string]*tls.Certificate
	cacheMu   sync.RWMutex
	// cachedCRL is a pre-built empty (valid) CRL in DER format.
	cachedCRL    []byte
	cachedCRLMu  sync.RWMutex
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

// TLSConfig returns a *tls.Config that uses GetConfigForClient to negotiate
// per-connection TLS settings after reading the ClientHello.
// This properly handles clients sending legacy TLS record headers (e.g. TLS 1.0).
func (ca *CA) TLSConfig() *tls.Config {
	return &tls.Config{
		SessionTicketsDisabled: true, // ensures GetConfigForClient is always called
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			domain := chi.ServerName
			if domain == "" {
				return nil, fmt.Errorf("mitm: no SNI in ClientHello")
			}
			cert, err := ca.GetOrCreateLeafCert(domain)
			if err != nil {
				return nil, err
			}
			cfg := &tls.Config{
				SessionTicketsDisabled: true,
				Certificates:           []tls.Certificate{*cert},
				MinVersion:             tls.VersionTLS10,
			}
			// Mirror the client's supported next-protocols (h2, http/1.1)
			if len(chi.SupportedProtos) > 0 {
				cfg.NextProtos = chi.SupportedProtos
			} else {
				cfg.NextProtos = []string{"http/1.1"}
			}
			return cfg, nil
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

	crlURL := crlDPBase + "/crl.der"
	ocspURL := crlDPBase + "/ocsp"

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// CRL Distribution Points — schannel requires at least one to perform
		// revocation check; we serve a valid empty CRL at this endpoint.
		CRLDistributionPoints: []string{crlURL},
		// OCSP — advertised so schannel can also try OCSP stapling path.
		OCSPServer: []string{ocspURL},
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

// BuildCRL generates a valid empty CRL signed by the CA and caches it.
// The CRL is valid for 24 hours. Call periodically to refresh.
func (ca *CA) BuildCRL() ([]byte, error) {
	ca.cachedCRLMu.RLock()
	if ca.cachedCRL != nil {
		ca.cachedCRLMu.RUnlock()
		return ca.cachedCRL, nil
	}
	ca.cachedCRLMu.RUnlock()

	return ca.refreshCRL()
}

func (ca *CA) refreshCRL() ([]byte, error) {
	now := time.Now()
	// x509.RevocationList is the modern API (Go 1.19+)
	template := &x509.RevocationList{
		SignatureAlgorithm:  x509.SHA256WithRSA,
		Number:              big.NewInt(1),
		ThisUpdate:          now,
		NextUpdate:          now.Add(24 * time.Hour),
		RevokedCertificates: []pkix.RevokedCertificate{}, // empty — no revoked certs
	}

	rsaKey, ok := ca.key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("mitm: CA key is not RSA, cannot sign CRL")
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, ca.cert, rsaKey)
	if err != nil {
		return nil, fmt.Errorf("mitm: create CRL: %w", err)
	}

	ca.cachedCRLMu.Lock()
	ca.cachedCRL = crlDER
	ca.cachedCRLMu.Unlock()

	return crlDER, nil
}

// ensure asn1 is imported (used indirectly by x509 pkix types)
var _ = asn1.Marshal

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
