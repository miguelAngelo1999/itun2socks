package conn

import (
	"context"
	"errors"
	"testing"

	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/clash/adapter"
	"github.com/igoogolx/itun2socks/pkg/clash/adapter/outbound"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The executor registers named proxies while building the tunnel, which happens
// before the selected proxy is installed. Writing into the live map at that point
// panicked with "assignment to entry in nil map" and took the core down on every
// connect.
func TestUpdateNamedProxiesBeforeUpdateProxy(t *testing.T) {
	proxies = nil
	namedProxies = map[constants.Policy]C.Proxy{}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked before UpdateProxy: %v", r)
		}
	}()

	direct := adapter.NewProxy(outbound.NewDirect())
	UpdateNamedProxies(map[string]C.Proxy{"proxy-abc": direct})

	if len(NamedProxyIds()) != 1 {
		t.Fatalf("expected 1 named proxy, got %d", len(NamedProxyIds()))
	}
}

// After UpdateProxy runs, a previously registered named proxy must be dialable.
func TestNamedProxySurvivesUpdateProxy(t *testing.T) {
	proxies = nil
	namedProxies = map[constants.Policy]C.Proxy{}

	direct := adapter.NewProxy(outbound.NewDirect())
	UpdateNamedProxies(map[string]C.Proxy{"proxy-abc": direct})
	UpdateProxy(direct)

	if _, err := GetProxy(constants.Policy("proxy-abc")); err != nil {
		t.Errorf("named proxy not dialable after UpdateProxy: %v", err)
	}
	for _, p := range []constants.Policy{constants.PolicyDirect, constants.PolicyProxy, constants.PolicyReject} {
		if _, err := GetProxy(p); err != nil {
			t.Errorf("built-in %s missing: %v", p, err)
		}
	}
}

// UpdateProxy rebuilds the map whenever selection changes; the named set has to
// survive that.
func TestNamedProxySurvivesRepeatedUpdateProxy(t *testing.T) {
	proxies = nil
	namedProxies = map[constants.Policy]C.Proxy{}

	direct := adapter.NewProxy(outbound.NewDirect())
	UpdateNamedProxies(map[string]C.Proxy{"proxy-abc": direct})
	UpdateProxy(direct)
	UpdateProxy(direct) // simulate the user switching proxy

	if _, err := GetProxy(constants.Policy("proxy-abc")); err != nil {
		t.Errorf("named proxy lost after a second UpdateProxy: %v", err)
	}
}

// A proxy id equal to a built-in policy name would shadow it.
func TestNamedProxyCannotShadowBuiltIn(t *testing.T) {
	proxies = nil
	namedProxies = map[constants.Policy]C.Proxy{}

	direct := adapter.NewProxy(outbound.NewDirect())
	UpdateNamedProxies(map[string]C.Proxy{"PROXY": direct, "ok-id": direct})

	for _, id := range NamedProxyIds() {
		if id == "PROXY" {
			t.Error("a proxy id of PROXY was accepted and would shadow the built-in")
		}
	}
}

func TestIsUpstreamAuthError(t *testing.T) {
	assert.False(t, isUpstreamAuthError(nil))
	assert.True(t, isUpstreamAuthError(errors.New("HTTP need auth")))
	assert.True(t, isUpstreamAuthError(errors.New("upstream proxy authentication required (HTTP 407)")))
	assert.False(t, isUpstreamAuthError(errors.New("connection timeout")))
}

type dummyRule struct {
	policy constants.Policy
}

func (d *dummyRule) Match(value string) bool    { return true }
func (d *dummyRule) Value() string              { return "" }
func (d *dummyRule) GetPolicy() constants.Policy { return d.policy }
func (d *dummyRule) Type() constants.RuleType   { return "" }
func (d *dummyRule) Valid() bool                { return true }

func TestNewUdpConnUnsupported(t *testing.T) {
	proxies = nil
	namedProxies = map[constants.Policy]C.Proxy{}

	httpProxy := adapter.NewProxy(outbound.NewHttp(outbound.HttpOption{
		Name:   "http-test",
		Server: "1.1.1.1",
		Port:   8080,
	}))
	UpdateProxy(httpProxy)

	_, err := NewUdpConn(context.Background(), &C.Metadata{DstPort: 3478}, &dummyRule{policy: constants.PolicyProxy}, "")
	require.Error(t, err)
	assert.Equal(t, "proxy does not support UDP", err.Error())
}

