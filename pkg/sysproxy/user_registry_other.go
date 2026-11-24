//go:build !windows

package sysproxy

// SetTargetUserSID is a no-op on non-Windows platforms.
func SetTargetUserSID(_ string) {}
