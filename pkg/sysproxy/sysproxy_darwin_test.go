//go:build darwin && !ios

package sysproxy

import "testing"

func TestLooksLikeDeviceName(t *testing.T) {
	devices := []string{"en0", "en1", "utun3", "bridge0", "awdl0", "llw0", "anpi1"}
	for _, d := range devices {
		if !looksLikeDeviceName(d) {
			t.Errorf("%q should be recognised as a device name", d)
		}
	}
	services := []string{"Wi-Fi", "Ethernet", "Thunderbolt Bridge", "USB 10/100/1000 LAN", "iPhone USB"}
	for _, s := range services {
		if looksLikeDeviceName(s) {
			t.Errorf("%q is a service name, not a device", s)
		}
	}
}

// A service name supplied by the caller is used verbatim.
func TestResolveServiceNameKeepsServiceName(t *testing.T) {
	got, err := resolveServiceName("Wi-Fi")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "Wi-Fi" {
		t.Errorf("got %q, want Wi-Fi", got)
	}
}

// An empty value is what Setting.HijackDns.NetworkService holds unless DNS
// hijacking was configured, and it made networksetup exit 4.
func TestResolveServiceNameFillsInEmpty(t *testing.T) {
	got, err := resolveServiceName("")
	if err != nil {
		t.Skipf("no active network service on this host: %v", err)
	}
	if got == "" {
		t.Error("resolved to an empty service name")
	}
	if looksLikeDeviceName(got) {
		t.Errorf("resolved to a device name %q; networksetup needs a service name", got)
	}
	t.Logf("resolved to %q", got)
}

// A device name must be translated rather than passed through.
func TestResolveServiceNameTranslatesDeviceName(t *testing.T) {
	got, err := resolveServiceName("en0")
	if err != nil {
		t.Skipf("no active network service on this host: %v", err)
	}
	if got == "en0" {
		t.Error("en0 was passed through; networksetup rejects device names with exit 4")
	}
	t.Logf("en0 resolved to %q", got)
}
