package conn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/igoogolx/itun2socks/internal/blackbox"
	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// errAuthLatched is returned for a proxy dial while the selected proxy's
// credentials are known-rejected (upstream 407). Failing fast here stops the
// core from re-attempting a known-bad password on every request.
var errAuthLatched = errors.New("proxy auth rejected — awaiting new credentials")

// isUpstreamAuthError reports whether a dial error came from the upstream proxy
// rejecting our credentials (e.g. HTTP 407).
func isUpstreamAuthError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "HTTP need auth") ||
		strings.Contains(s, "upstream proxy authentication required") ||
		strings.Contains(s, "HTTP 407")
}

func isWhatsAppTraffic(metadata *C.Metadata) bool {
	if metadata == nil {
		return false
	}
	if metadata.DstPort == 5222 {
		return true
	}
	host := strings.ToLower(metadata.Host)
	if strings.HasSuffix(host, ".whatsapp.com") || host == "whatsapp.com" ||
		strings.HasSuffix(host, ".whatsapp.net") || host == "whatsapp.net" {
		return true
	}
	return false
}

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
	if proxyId != "" && metadata.Host != "" && !pac.DefaultRegistry.IsPacOnly(proxyId) {
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

	// WhatsApp signaling (port 5222 / XMPP) and WhatsApp traffic to non-SSL ports:
	// HTTP proxies (Squid, etc.) only permit CONNECT to SSL port 443 and reject
	// port 5222 with HTTP 403 Forbidden.
	// Route WhatsApp signaling directly via physical interface, matching System proxy mode.
	if policy != constants.PolicyDirect && isWhatsAppTraffic(metadata) && (metadata.DstPort == 5222 || connDialer.Type() == C.Http && metadata.DstPort != 443) {
		log.Infoln(log.FormatLog(log.TcpPrefix, "WhatsApp signaling (%v:%v) bypasses proxy to DIRECT"),
			metadata.Host, metadata.DstPort)
		directDialer, dErr := GetProxy(constants.PolicyDirect)
		if dErr == nil {
			return directDialer.DialContext(ctx, metadata, dialer.WithInterface(defaultInterface))
		}
	}

	// This is a proxy dial. If the upstream has already rejected our
	// credentials (407), fail fast instead of re-attempting the known-bad
	// password on every request — the UI has been prompted to fix it and the
	// latch clears when the manager restarts with new creds.
	if blackbox.IsAuthLatched() {
		return nil, errAuthLatched
	}

	c, err := connDialer.DialContext(ctx, metadata, dialer.WithInterface(""))
	if err != nil && isUpstreamAuthError(err) {
		// Upstream rejected the credentials: latch + notify the UI (debounced
		// inside ReportAuthFailed) so the user is asked to retype, and stop
		// retrying this proxy until they do.
		blackbox.ReportAuthFailed(connDialer.Addr())
	}
	return c, err
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
