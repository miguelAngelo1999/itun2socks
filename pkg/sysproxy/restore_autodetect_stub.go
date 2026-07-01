//go:build !windows

package sysproxy

// RestoreAutoDetectOnExit is a no-op on non-Windows platforms.
// On Windows it controls whether "Automatically detect settings" is
// restored when lux disconnects. See sysproxy_windows.go.
var RestoreAutoDetectOnExit bool
