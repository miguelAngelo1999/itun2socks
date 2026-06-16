package mitm

import (
"crypto/tls"
"crypto/x509"
"os"
"testing"
"time"
)

// newTestCA creates a CA in a temp dir for testing.
func newTestCA(t *testing.T) (*CA, string) {
t.Helper()
dir := t.TempDir()
ca, err := Init(dir)
if err != nil {
t.Fatalf("Init failed: %v", err)
}
return ca, dir
}

// TestCAInit verifies that Init generates a CA and persists it.
func TestCAInit(t *testing.T) {
ca, dir := newTestCA(t)

if ca.cert == nil {
t.Fatal("CA cert is nil after Init")
}
if ca.key == nil {
t.Fatal("CA key is nil after Init")
}
if len(ca.CertPEM()) == 0 {
t.Fatal("CertPEM() returned empty slice")
}
if len(ca.CertDER()) == 0 {
t.Fatal("CertDER() returned empty slice")
}

// Files must exist on disk
if _, err := os.Stat(dir + "/mitm_ca.crt"); err != nil {
t.Fatalf("mitm_ca.crt not found: %v", err)
}
if _, err := os.Stat(dir + "/mitm_ca_key.enc"); err != nil {
t.Fatalf("mitm_ca_key.enc not found: %v", err)
}

// CN must be correct
if ca.cert.Subject.CommonName != "Lux SSL Inspection CA" {
t.Errorf("unexpected CN: %s", ca.cert.Subject.CommonName)
}

// Validity: 10 years ± 1 day
want := 10 * 365 * 24 * time.Hour
got := ca.cert.NotAfter.Sub(ca.cert.NotBefore)
if got < want-24*time.Hour || got > want+24*time.Hour {
t.Errorf("CA validity = %v, want ~%v", got, want)
}

// Must be a CA
if !ca.cert.IsCA {
t.Error("CA cert IsCA == false")
}
}

// TestCALoadRoundTrip verifies that calling Init twice uses the persisted CA.
func TestCALoadRoundTrip(t *testing.T) {
ca1, dir := newTestCA(t)

ca2, err := Init(dir)
if err != nil {
t.Fatalf("second Init failed: %v", err)
}

// Fingerprints must match
if ca1.Fingerprint() != ca2.Fingerprint() {
t.Errorf("fingerprint mismatch after reload:\n  first:  %s\n  second: %s",
ca1.Fingerprint(), ca2.Fingerprint())
}
}

// TestCAFingerprintStable verifies the fingerprint is deterministic.
func TestCAFingerprintStable(t *testing.T) {
ca, _ := newTestCA(t)

fp1 := ca.Fingerprint()
fp2 := ca.Fingerprint()
if fp1 != fp2 {
t.Error("Fingerprint() returned different values on consecutive calls")
}
if len(fp1) == 0 {
t.Error("Fingerprint() returned empty string")
}
// Format: "XX:XX:..." — 32 two-hex-char groups separated by colons
// SHA-256 is 32 bytes → 32 groups → 32*3 - 1 = 95 chars
if len(fp1) != 95 {
t.Errorf("Fingerprint() length = %d, want 95", len(fp1))
}
}

// TestGetOrCreateLeafCert_Basic verifies a leaf cert is created and signed by the CA.
func TestGetOrCreateLeafCert_Basic(t *testing.T) {
ca, _ := newTestCA(t)

domain := "example.com"
leafCert, err := ca.GetOrCreateLeafCert(domain)
if err != nil {
t.Fatalf("GetOrCreateLeafCert(%q): %v", domain, err)
}
if leafCert == nil {
t.Fatal("returned nil leaf cert")
}
if leafCert.Leaf == nil {
t.Fatal("leaf cert Leaf field is nil")
}

// SAN must contain the domain
found := false
for _, san := range leafCert.Leaf.DNSNames {
if san == domain {
found = true
break
}
}
if !found {
t.Errorf("SAN does not contain %q; got %v", domain, leafCert.Leaf.DNSNames)
}

// Validity: ~24 hours
validity := leafCert.Leaf.NotAfter.Sub(leafCert.Leaf.NotBefore)
if validity < 23*time.Hour || validity > 25*time.Hour {
t.Errorf("leaf cert validity = %v, want ~24h", validity)
}
}

// TestLeafCertValidatesAgainstCA verifies the leaf cert chain validates to the CA.
func TestLeafCertValidatesAgainstCA(t *testing.T) {
ca, _ := newTestCA(t)

domain := "test.example.com"
leafCert, err := ca.GetOrCreateLeafCert(domain)
if err != nil {
t.Fatalf("GetOrCreateLeafCert: %v", err)
}

// Build a certificate pool with our CA
pool := x509.NewCertPool()
pool.AddCert(ca.cert)

opts := x509.VerifyOptions{
DNSName: domain,
Roots:   pool,
// Leaf certs have a 24h validity — set current time within that window
CurrentTime: leafCert.Leaf.NotBefore.Add(time.Hour),
}
if _, err := leafCert.Leaf.Verify(opts); err != nil {
t.Errorf("leaf cert does not validate against CA: %v", err)
}
}

// TestLeafCertCacheReturnsSameCert verifies that two calls for the same domain return the same cert.
func TestLeafCertCacheReturnsSameCert(t *testing.T) {
ca, _ := newTestCA(t)

domain := "cache-test.example.com"
cert1, err := ca.GetOrCreateLeafCert(domain)
if err != nil {
t.Fatalf("first GetOrCreateLeafCert: %v", err)
}
cert2, err := ca.GetOrCreateLeafCert(domain)
if err != nil {
t.Fatalf("second GetOrCreateLeafCert: %v", err)
}

if cert1 != cert2 {
t.Error("cache miss: second call returned a different *tls.Certificate pointer")
}
}

// TestLeafCertExpiredIsRegenerated verifies expired certs are regenerated.
func TestLeafCertExpiredIsRegenerated(t *testing.T) {
ca, _ := newTestCA(t)

domain := "expired-test.example.com"

// Manually insert an expired cert into the cache
expired := &tls.Certificate{
Leaf: &x509.Certificate{
NotBefore: time.Now().Add(-48 * time.Hour),
NotAfter:  time.Now().Add(-1 * time.Hour), // already expired
},
}
ca.cacheMu.Lock()
ca.leafCache[domain] = expired
ca.cacheMu.Unlock()

// GetOrCreateLeafCert should detect the expiry and generate a fresh cert
fresh, err := ca.GetOrCreateLeafCert(domain)
if err != nil {
t.Fatalf("GetOrCreateLeafCert: %v", err)
}
if fresh == expired {
t.Error("expected a new cert to be generated for an expired cached cert")
}
if time.Now().After(fresh.Leaf.NotAfter) {
t.Error("newly generated cert is already expired")
}
}

// TestTLSConfig verifies TLSConfig returns a config with a working GetCertificate callback.
func TestTLSConfig(t *testing.T) {
ca, _ := newTestCA(t)

tlsCfg := ca.TLSConfig()
if tlsCfg == nil {
t.Fatal("TLSConfig() returned nil")
}
if tlsCfg.GetCertificate == nil {
t.Fatal("TLSConfig().GetCertificate is nil")
}

// Exercise the callback
hello := &tls.ClientHelloInfo{ServerName: "callback-test.example.com"}
cert, err := tlsCfg.GetCertificate(hello)
if err != nil {
t.Fatalf("GetCertificate callback: %v", err)
}
if cert == nil {
t.Fatal("GetCertificate callback returned nil cert")
}
}

// TestGeneratedAt verifies GeneratedAt returns the CA's NotBefore time.
func TestGeneratedAt(t *testing.T) {
before := time.Now().Add(-time.Second)
ca, _ := newTestCA(t)
after := time.Now().Add(time.Second)

generatedAt := ca.GeneratedAt()
if generatedAt.Before(before) || generatedAt.After(after) {
t.Errorf("GeneratedAt() = %v, expected between %v and %v", generatedAt, before, after)
}
}
