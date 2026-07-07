//go:build !windows

package main

// killStaleLuxCore is a no-op on non-Windows platforms.
// macOS handles process cleanup via launchd / process groups.
func killStaleLuxCore() {}
