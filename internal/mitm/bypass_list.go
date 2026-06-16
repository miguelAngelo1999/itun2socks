package mitm

import (
"sort"
"strings"
)

// bypassPatterns lists domain patterns that must never be TLS-inspected.
// These cover banking/financial institutions, certificate-pinned services,
// and OCSP/CRL infrastructure. Patterns with "*."-prefix match the base domain
// and all subdomains; exact patterns (no "*." prefix) match only that host.
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
// It checks for an exact hostname match, and for wildcard patterns ("*.suffix")
// it checks whether domain equals the suffix or ends with "."+suffix.
func IsBypassed(domain string) bool {
domain = strings.ToLower(strings.TrimSpace(domain))
for _, pattern := range bypassPatterns {
if strings.HasPrefix(pattern, "*.") {
// Wildcard: strip "*."; match base domain and subdomains
suffix := strings.ToLower(pattern[2:])
if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
return true
}
} else {
// Exact pattern
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
