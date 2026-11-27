//go:build !darwin && !windows

package routes

import "crypto/x509"

func isTrustedBumpCert(_ *x509.Certificate, _ [][]*x509.Certificate, _ *x509.CertPool, _ string) bool {
	return false
}
