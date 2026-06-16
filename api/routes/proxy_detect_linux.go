//go:build linux

package routes

// detectNetworkProxy is a no-op on Linux; proxy detection is not implemented.
func detectNetworkProxy() ProxyDetectResult {
	return ProxyDetectResult{Detected: false}
}

// extractFirstProxyFromPAC is shared logic referenced by the linux build.
// On Linux no PAC fetching is done, so this is just a stub to satisfy the
// compiler when building for linux targets.
func extractFirstProxyFromPAC(_ string) (string, string) { return "", "" }

// probeProxy is a no-op stub for linux.
func probeProxy(_ *DetectedProxy) {}
