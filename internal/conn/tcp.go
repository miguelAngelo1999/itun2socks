package conn

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
	"github.com/igoogolx/itun2socks/pkg/log"
)

type TcpConnContext struct {
	ctx      context.Context
	metadata *C.Metadata
	conn     net.Conn
	rule     rule_engine.Rule
	wg       *sync.WaitGroup
}

func (t *TcpConnContext) Wg() *sync.WaitGroup {
	return t.wg
}

func (t *TcpConnContext) Ctx() context.Context {
	return t.ctx
}

func (t *TcpConnContext) Rule() rule_engine.Rule {
	return t.rule
}

func (t *TcpConnContext) Metadata() *C.Metadata {
	return t.metadata
}

func (t *TcpConnContext) Conn() net.Conn {
	return t.conn
}

func NewTcpConnContext(ctx context.Context, conn net.Conn, metadata *C.Metadata, wg *sync.WaitGroup) (*TcpConnContext, error) {

	rule := handleMetadata(metadata)

	var connContext = &TcpConnContext{
		ctx,
		metadata,
		conn,
		rule,
		wg,
	}
	return connContext, nil

}

func NewTcpConn(ctx context.Context, metadata *C.Metadata, rule rule_engine.Rule, defaultInterface string) (net.Conn, error) {
	policy := rule.GetPolicy()

	// Per-proxy PAC: if the rule chose a named proxy, consult that proxy's PAC
	// before dialing. If the PAC says DIRECT, bypass the proxy entirely.
	//
	// This runs AFTER rule matching (custom rules already won) and BEFORE
	// dialing, so it cannot override a user's explicit rule — it only provides a
	// secondary filter within the chosen proxy's scope.
	//
	// Also applies to the "selected" proxy (PolicyProxy): it's just another proxy
	// with an id, and its PAC is in the same registry.
	proxyId := proxyIdForPolicy(policy)
	if proxyId == "" && policy == constants.PolicyProxy {
		proxyId = GetSelectedProxyId()
	}
	if proxyId != "" && metadata.Host != "" {
		port := fmt.Sprintf("%d", metadata.DstPort)
		isTLS := metadata.DstPort == 443
		if pac.DefaultRegistry.ShouldDirect(proxyId, metadata.Host, port, isTLS) {
			log.Debugln("[pac-proxy] %s:%s → DIRECT (proxy %s PAC override)", metadata.Host, port, proxyId)
			directDialer, err := GetProxy(constants.PolicyDirect)
			if err != nil {
				return nil, err
			}
			return directDialer.DialContext(ctx, metadata, dialer.WithInterface(defaultInterface))
		}
	}

	connDialer, err := GetProxy(policy)
	if err != nil {
		return nil, err
	}
	// Proxy connections must NOT be bound to a specific interface.
	// DefaultInterface is set globally (to en0), but proxy servers may be
	// reachable only through a different interface (VPN, utun7, etc).
	// Passing WithInterface("") overrides the default and lets the kernel
	// route through whatever interface the proxy server's subnet requires.
	if policy == constants.PolicyDirect {
		return connDialer.DialContext(ctx, metadata, dialer.WithInterface(defaultInterface))
	}
	return connDialer.DialContext(ctx, metadata, dialer.WithInterface(""))
}

// proxyIdForPolicy returns the proxy id if the policy targets a named proxy,
// or "" for built-in policies (DIRECT, PROXY, REJECT).
func proxyIdForPolicy(p constants.Policy) string {
	if constants.IsBuiltInPolicy(p) {
		return ""
	}
	// A non-builtin policy is a proxy id.
	return string(p)
}
