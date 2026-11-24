//go:build !windows

package conn

func isUdpConnResetError(_ error) bool {
	return false
}
