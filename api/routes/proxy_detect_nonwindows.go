//go:build !windows

package routes

// probeWindowsRegistry is a no-op on non-Windows platforms.
func probeWindowsRegistry() DetectedProxy { return DetectedProxy{Found: false} }

// probeNetshWinhttp is a no-op on non-Windows platforms.
func probeNetshWinhttp() DetectedProxy { return DetectedProxy{Found: false} }
