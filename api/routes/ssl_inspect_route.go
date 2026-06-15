package routes

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	ssl "github.com/igoogolx/itun2socks/internal/ssl_inspect"
)

var (
	lastSslCheck  time.Time
	lastSslStatus ssl.BumpStatus
)

// CertInfo contains human-readable fields from the intercepting CA cert.
type CertInfo struct {
	Subject            string `json:"subject"`
	Issuer             string `json:"issuer"`
	NotBefore          string `json:"notBefore"`
	NotAfter           string `json:"notAfter"`
	SHA256Fingerprint  string `json:"sha256Fingerprint"`
	IsCA               bool   `json:"isCA"`
	OrganizationName   string `json:"organizationName"`
}

// sslInspectRouter returns a chi.Router for /ssl-inspect/*.
func sslInspectRouter() chi.Router {
	r := chi.NewRouter()
	r.Get("/status", sslInspectStatus)
	r.Get("/cert", sslInspectCert)
	return r
}

// sslInspectStatus probes for SSL bumping and returns JSON including cert metadata.
func sslInspectStatus(w http.ResponseWriter, r *http.Request) {
	const minInterval = 30 * time.Second
	if time.Since(lastSslCheck) > minInterval {
		status := ssl.Detect()
		if status.Detected && len(status.InterceptCA) > 0 {
			ssl.Cache(status.InterceptCA)
		}
		lastSslCheck = time.Now()
		lastSslStatus = status
	}

	resp := map[string]interface{}{
		"detected":  lastSslStatus.Detected,
		"checkedAt": lastSslCheck.Format(time.RFC3339),
		"error":     lastSslStatus.Error,
		"hasCert":   len(ssl.PEM()) > 0,
	}

	// Include cert metadata when a cert is available so the UI can show it
	// before the user decides whether to trust it
	if der, _ := ssl.Cached(); len(der) > 0 {
		if info := parseCertInfo(der); info != nil {
			resp["certInfo"] = info
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// sslInspectCert returns the intercepting CA cert as PEM text.
// Returns 404 if no cert has been captured yet.
func sslInspectCert(w http.ResponseWriter, r *http.Request) {
	p := ssl.PEM()
	if len(p) == 0 {
		http.Error(w, "no certificate captured", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="lux_intercept_ca.pem"`)
	_, _ = w.Write(p)
}

// parseCertInfo extracts human-readable fields from a DER-encoded certificate.
func parseCertInfo(der []byte) *CertInfo {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	fp := sha256.Sum256(der)
	fpHex := hex.EncodeToString(fp[:])
	// Format as colon-separated pairs for readability: AA:BB:CC:...
	formatted := ""
	for i := 0; i < len(fpHex); i += 2 {
		if i > 0 {
			formatted += ":"
		}
		formatted += fpHex[i : i+2]
	}

	org := ""
	if len(cert.Subject.Organization) > 0 {
		org = cert.Subject.Organization[0]
	}

	return &CertInfo{
		Subject:           cert.Subject.CommonName,
		Issuer:            cert.Issuer.CommonName,
		NotBefore:         cert.NotBefore.Format("2006-01-02"),
		NotAfter:          cert.NotAfter.Format("2006-01-02"),
		SHA256Fingerprint: formatted,
		IsCA:              cert.IsCA,
		OrganizationName:  org,
	}
}
