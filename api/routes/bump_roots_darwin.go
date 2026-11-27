//go:build darwin

package routes

import (
	"crypto/x509"
	"os/exec"
	"sync"
)

var (
	applePublicRootsOnce sync.Once
	applePublicRootsPool *x509.CertPool
)

// loadApplePublicRoots loads macOS's SIP-protected built-in public root CA
// bundle (/System/Library/Keychains/SystemRootCertificates.keychain). Corporate,
// MDM, and Lux-installed SSL-bump CAs live in /Library/Keychains/System.keychain
// or login.keychain and are never present in SystemRootCertificates.keychain.
func loadApplePublicRoots() *x509.CertPool {
	applePublicRootsOnce.Do(func() {
		out, err := exec.Command(
			"/usr/bin/security",
			"find-certificate", "-a", "-p",
			"/System/Library/Keychains/SystemRootCertificates.keychain",
		).Output()
		if err != nil || len(out) == 0 {
			return
		}
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(out) {
			applePublicRootsPool = pool
		}
	})
	return applePublicRootsPool
}

// isTrustedBumpCert reports whether a leaf certificate that passed full OS
// verification was actually signed by a trusted custom / corporate SSL-bump CA
// rather than a built-in public internet root CA.
func isTrustedBumpCert(leaf *x509.Certificate, verifiedChains [][]*x509.Certificate, intermediates *x509.CertPool, sni string) bool {
	if leaf == nil {
		return false
	}
	pubRoots := loadApplePublicRoots()
	if pubRoots != nil {
		// If the leaf verifies against Apple's built-in public CAs, it is a normal
		// public website certificate (no SSL bump). If it fails against Apple's
		// built-in public CAs despite passing full OS verification, it was signed
		// by a trusted custom/corporate root CA in System.keychain / login.keychain!
		_, err := leaf.Verify(x509.VerifyOptions{
			DNSName:       sni,
			Roots:         pubRoots,
			Intermediates: intermediates,
		})
		return err != nil
	}
	// Fallback if SystemRootCertificates.keychain was unavailable: check if any
	// root in verifiedChains is in /Library/Keychains/System.keychain.
	for _, chain := range verifiedChains {
		if len(chain) > 0 && isCertInSystemStore(chain[len(chain)-1]) {
			return true
		}
	}
	return false
}
