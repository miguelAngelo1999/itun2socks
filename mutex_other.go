//go:build !windows

package main

func ensureSingleInstance() {
	// No-op on non-Windows platforms
}
