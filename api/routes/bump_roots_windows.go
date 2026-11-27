//go:build windows

package routes

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func regKeyExists(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

// isTrustedBumpCert reports whether a leaf certificate that passed full Windows
// verification was signed by a trusted custom / corporate SSL-bump CA rather
// than a standard public root CA from Microsoft's Trusted Root Program.
func isTrustedBumpCert(leaf *x509.Certificate, verifiedChains [][]*x509.Certificate, _ *x509.CertPool, _ string) bool {
	if leaf == nil || len(verifiedChains) == 0 {
		return false
	}

	// Well-known public root CA org substrings shipped in Windows LocalMachine\Root.
	publicRoots := []string{
		"digicert", "baltimore", "entrust", "globalsign", "godaddy", "starfield",
		"comodo", "sectigo", "usertrust", "aaa certificate", "identrust",
		"isrg", "let's encrypt", "google trust", "amazon", "microsoft",
		"cloudflare", "verisign", "thawte", "geotrust", "symantec",
		"quovadis", "swisssign", "buypass", "certum", "actalis", "ssl.com",
		"globalsign", "addtrust", "t-systems", "telia", "harica", "naver",
		"certainly", "zerossl", "rapidssl", "emSign", "affirmtrust",
	}

	for _, chain := range verifiedChains {
		if len(chain) == 0 {
			continue
		}
		root := chain[len(chain)-1]
		sum := sha1.Sum(root.Raw)
		thumb := strings.ToUpper(hex.EncodeToString(sum[:]))

		// 1. Explicitly installed in Enterprise / GPO Policy / CurrentUser Root -> custom CA.
		if regKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates\`+thumb) ||
			regKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates\`+thumb) ||
			regKeyExists(registry.CURRENT_USER, `SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\`+thumb) {
			return true
		}

		// 2. Present in Microsoft's public third-party AuthRoot -> public CA, not bump.
		if regKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates\`+thumb) {
			return false
		}

		// 3. Present in LocalMachine\Root (where Lux / IT installers put custom CAs)
		// and NOT a well-known public internet root CA -> custom bump CA.
		if regKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\`+thumb) {
			issuerLower := strings.ToLower(certIssuerName(root.Issuer))
			isPublic := false
			for _, pub := range publicRoots {
				if strings.Contains(issuerLower, strings.ToLower(pub)) {
					isPublic = true
					break
				}
			}
			if !isPublic {
				return true
			}
		}
	}

	return false
}
