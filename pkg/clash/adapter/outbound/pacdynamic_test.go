package outbound

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
)

func TestPacDynamic_PrivateUpstreamDoesNotForceDefaultInterface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`
function FindProxyForURL(url, host) {
    if (host == "private.test") return "PROXY 10.8.0.1:8082";
    return "PROXY 203.0.113.1:8082";
}`))
	}))
	defer srv.Close()

	pac.DefaultRegistry.Clear()
	t.Cleanup(func() {
		pac.DefaultRegistry.Clear()
		pac.SetIsBypassed(nil)
	})
	pac.SetIsBypassed(func(net.IP) bool { return false })
	pac.DefaultRegistry.Update([]map[string]any{
		{"id": "pac-only-1", "server": "", "pacUrl": srv.URL},
	}, "")

	prevIface := dialer.DefaultInterface.Load()
	dialer.DefaultInterface.Store("nonexistent-iface0")
	t.Cleanup(func() { dialer.DefaultInterface.Store(prevIface) })

	p := NewPacDynamic(PacDynamicOption{
		Name:    "pac-test",
		ProxyId: "pac-only-1",
	})

	// 1. Private upstream (10.8.0.1): must NOT bind defIface ("nonexistent-iface0"),
	// so dial reaches TCP attempt (timeout/refused) instead of failing interface lookup.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel1()
	_, err := p.DialContext(ctx1, &C.Metadata{Host: "private.test", DstPort: 443}, dialer.WithInterface(""))
	if err == nil {
		t.Fatalf("expected dial error to unreachable 10.8.0.1:8082")
	}
	if strings.Contains(err.Error(), "interface not found") {
		t.Fatalf("private upstream 10.8.0.1 must not force DefaultInterface, got err: %v", err)
	}

	// 2. Public non-bypassed upstream (203.0.113.1): MUST bind defIface to avoid TUN loop,
	// which triggers interface lookup error ("interface not found").
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	_, err2 := p.DialContext(ctx2, &C.Metadata{Host: "public.test", DstPort: 443}, dialer.WithInterface(""))
	if err2 == nil || !strings.Contains(err2.Error(), "interface not found") {
		t.Fatalf("public non-bypassed upstream should bind DefaultInterface, got err: %v", err2)
	}
}
