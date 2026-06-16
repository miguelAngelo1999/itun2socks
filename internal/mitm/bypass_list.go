package mitm

import (
	"sort"
	"strings"
)

// bypassPatterns lists domain patterns that must never be TLS-inspected.
// Covers banking/financial institutions, certificate-pinned services, and OCSP/CRL infra.
var bypassPatterns = []string{
	// Banking and financial
	"*.chase.com",
	"*.bankofamerica.com",
	"*.wellsfargo.com",
	"*.citibank.com",
	"*.hsbc.com",
	"*.barclays.com",
	"*.lloydsbank.com",
	"*.santander.com",
	"*.paypal.com",
	"*.stripe.com",
	"*.square.com",
	"*.db.com",
	// Certificate-pinned services
	"*.google.com",
	"*.gstatic.com",
	"*.googleapis.com",
	"*.apple.com",
	"*.icloud.com",
	"*.microsoft.com",
	"*.microsoftonline.com",
	"*.live.com",
	"*.windowsupdate.com",
	"update.microsoft.com",
	// OCSP / CRL infrastructure
	"*.ocsp.digicert.com",
	"*.crl.verisign.com",
	"*.pki.goog",
}

// IsBypassed reports whether domain is covered by the hardcoded bypass list.
func IsBypassed(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, pattern := range bypassPatterns {
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.ToLower(pattern[2:])
			if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
				return true
			}
		} else {
			if domain == strings.ToLower(pattern) {
				return true
			}
		}
	}
	return false
}

// GetBypassList returns a sorted copy of the bypass patterns for API exposure.
func GetBypassList() []string {
	result := make([]string, len(bypassPatterns))
	copy(result, bypassPatterns)
	sort.Strings(result)
	return result
}
