package routes

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// generateTestCACert generates a self-signed root CA certificate for testing.
func generateTestCACert(commonName string) (*x509.Certificate, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Lux Test CA Corp"},
			CommonName:   commonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return cert, pemBytes, nil
}

func TestFetchDirectCA_Primary(t *testing.T) {
	_, caPem, err := generateTestCACert("Primary Root CA")
	if err != nil {
		t.Fatalf("generateTestCACert failed: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/root-ca" {
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.WriteHeader(http.StatusOK)
			w.Write(caPem)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	// Extract host:port
	hostPort := strings.TrimPrefix(server.URL, "http://")
	ca, pemBytes, err := fetchDirectCA(hostPort)
	if err != nil {
		t.Fatalf("fetchDirectCA failed: %v", err)
	}

	if ca.Subject.CommonName != "Primary Root CA" {
		t.Errorf("expected CommonName 'Primary Root CA', got %q", ca.Subject.CommonName)
	}
	if !strings.Contains(string(pemBytes), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("expected PEM block, got %s", string(pemBytes))
	}
}

func TestFetchDirectCA_Fallback9876(t *testing.T) {
	_, caPem, err := generateTestCACert("Fallback 9876 Root CA")
	if err != nil {
		t.Fatalf("generateTestCACert failed: %v", err)
	}

	// Listen on 127.0.0.1:9876 if available, or test handler directly
	l, err := net.Listen("tcp", "127.0.0.1:9876")
	if err != nil {
		t.Skipf("cannot bind port 9876 on this host: %v", err)
	}
	defer l.Close()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/download/cas" {
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.WriteHeader(http.StatusOK)
			w.Write(caPem)
			return
		}
		http.NotFound(w, r)
	}))
	server.Listener = l
	server.Start()
	defer server.Close()

	ca, pemBytes, err := fetchDirectCA("127.0.0.1")
	if err != nil {
		t.Fatalf("fetchDirectCA fallback failed: %v", err)
	}

	if ca.Subject.CommonName != "Fallback 9876 Root CA" {
		t.Errorf("expected CommonName 'Fallback 9876 Root CA', got %q", ca.Subject.CommonName)
	}
	if !strings.Contains(string(pemBytes), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("expected PEM block, got %s", string(pemBytes))
	}
}
