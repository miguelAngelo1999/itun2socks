//go:build !windows

package executor

// enableUWPLoopback is a no-op on non-Windows platforms.
func enableUWPLoopback() {}
