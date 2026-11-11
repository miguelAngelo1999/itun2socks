package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/igoogolx/itun2socks/internal/pac"
	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
	"github.com/igoogolx/itun2socks/pkg/log"
)

// PacDynamic is a "PAC-only" outbound: it has no fixed upstream server. For each
// connection it evaluates the proxy's PAC against the destination and dials
// through whichever upstream the PAC selected (PROXY/SOCKS host:port), or
// connects directly if the PAC returned DIRECT for that destination.
//
// The upstream dialers it builds are cached and keyed by scheme|host:port|user,
// so a PAC that returns the same handful of proxies reuses a small set of
// child outbounds rather than constructing one per connection.
//
// Design notes (see PAC-only design, Option A):
//   - It reuses the existing Http/Socks5 outbound constructors, so auth, TLS and
//     the CONNECT handshake are handled exactly as a normal server proxy would.
//   - A PAC that returns DIRECT per connection is honored per connection.
//   - A PAC eval timeout/failure FAILS the dial (never silently goes DIRECT),
//     so a misbehaving PAC cannot leak traffic around the proxy. The registry's
//     own 200ms watchdog returns "DIRECT" on timeout, which here is treated as a
//     real DIRECT instruction only when the PAC genuinely resolves to DIRECT —
//     an empty/absent PAC (hasPAC == false) is the failure case and errors out.
type PacDynamic struct {
	*Base
	proxyId string
	// user/pass supplied on the PAC-only proxy, applied to every upstream the
	// PAC selects (PAC files carry no credentials).
	user string
	pass string

	mu    sync.Mutex
	cache map[string]C.ProxyAdapter // keyed by scheme|host:port|user
}

type PacDynamicOption struct {
	BasicOption
	Name     string
	ProxyId  string
	UserName string
	Password string
}

// cacheKey builds the LRU-ish cache key for an upstream.
func (p *PacDynamic) cacheKey(d pac.Directive) string {
	return d.Scheme + "|" + net.JoinHostPort(d.Host, d.Port) + "|" + p.user
}

// upstreamFor returns (and caches) the child outbound that reaches the given
// directive's upstream. direct directives return (nil, nil).
func (p *PacDynamic) upstreamFor(d pac.Directive) (C.ProxyAdapter, error) {
	if d.IsDirect() {
		return nil, nil
	}

	port, err := strconv.Atoi(d.Port)
	if err != nil {
		return nil, fmt.Errorf("pac-dynamic: bad port %q: %w", d.Port, err)
	}

	key := p.cacheKey(d)

	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.cache[key]; ok {
		return existing, nil
	}

	var adapter C.ProxyAdapter
	switch d.Scheme {
	case "http":
		adapter = NewHttp(HttpOption{
			Name:     p.Name() + "-upstream",
			Server:   d.Host,
			Port:     port,
			UserName: p.user,
			Password: p.pass,
		})
	case "socks5":
		adapter = NewSocks5(Socks5Option{
			Name:     p.Name() + "-upstream",
			Server:   d.Host,
			Port:     port,
			UserName: p.user,
			Password: p.pass,
		})
	default:
		return nil, fmt.Errorf("pac-dynamic: unsupported scheme %q", d.Scheme)
	}

	p.cache[key] = adapter
	return adapter, nil
}

// evalURL builds the FindProxyForURL(url, host) url argument from metadata.
func evalURL(metadata *C.Metadata) (url, host string) {
	host = metadata.String()
	scheme := "http"
	if metadata.DstPort == 443 {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%s/", scheme, host, metadata.DstPort.String()), host
}

// DialContext implements C.ProxyAdapter.
func (p *PacDynamic) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	url, host := evalURL(metadata)

	directive, hasPAC, timedOut := pac.DefaultRegistry.EvalDirective(p.proxyId, url, host)
	if !hasPAC {
		// No compiled PAC for this PAC-only proxy means we have no upstream to
		// dial. Fail the dial rather than leak traffic DIRECT.
		return nil, fmt.Errorf("pac-dynamic: no PAC available for proxy %s (dest %s)", p.proxyId, host)
	}
	if timedOut {
		// Ambiguous: a timeout is not a resolved DIRECT. Fail rather than leak
		// the connection around the proxy.
		return nil, fmt.Errorf("pac-dynamic: PAC eval timed out for proxy %s (dest %s)", p.proxyId, host)
	}

	// The PAC may return an ordered failover list; try each in order.
	directives := pac.ParseDirectives(directive)
	var lastErr error
	for _, d := range directives {
		if d.IsDirect() {
			var targetIP net.IP
			if ip := net.ParseIP(metadata.Host); ip != nil {
				targetIP = ip
			} else if metadata.DstIP != nil {
				targetIP = metadata.DstIP
			} else if ipStr := pac.GoLookup(metadata.Host); ipStr != "" {
				targetIP = net.ParseIP(ipStr)
			}

			directOpts := opts
			defIface := dialer.DefaultInterface.Load()
			// If target IP is NOT covered by bypass excluded prefixes and is NOT a private IP
			// (which could be routed over a corporate VPN utun interface), bind default interface
			// to prevent entering TUN and creating a routing loop (matching conn/tcp.go:118).
			if defIface != "" && targetIP != nil && !pac.IsBypassed(targetIP) && !targetIP.IsPrivate() {
				directOpts = append(directOpts, dialer.WithInterface(defIface))
			}

			c, err := dialer.DialContext(ctx, "tcp", metadata.RemoteAddress(), p.Base.DialOptions(directOpts...)...)
			if err != nil {
				lastErr = err
				continue
			}
			tcpKeepAlive(c)
			return NewConn(c, p), nil
		}

		var upstreamIP net.IP
		if ip := net.ParseIP(d.Host); ip != nil {
			upstreamIP = ip
		} else if ipStr := pac.GoLookup(d.Host); ipStr != "" {
			upstreamIP = net.ParseIP(ipStr)
		}

		childOpts := opts
		defIface := dialer.DefaultInterface.Load()
		if defIface != "" && upstreamIP != nil && !pac.IsBypassed(upstreamIP) && !upstreamIP.IsPrivate() {
			childOpts = append(childOpts, dialer.WithInterface(defIface))
		}

		upstream, err := p.upstreamFor(d)
		if err != nil {
			lastErr = err
			continue
		}
		conn, err := upstream.DialContext(ctx, metadata, childOpts...)
		if err != nil {
			lastErr = err
			log.Debugln("[pac-dynamic] upstream %s://%s dial failed for %s: %v", d.Scheme, net.JoinHostPort(d.Host, d.Port), host, err)
			continue
		}
		return conn, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("pac-dynamic: no usable upstream for %s", host)
	}
	return nil, lastErr
}

// Reset drops all cached upstream dialers. Call on config change / disconnect,
// alongside the PAC registry's Clear().
func (p *PacDynamic) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cache = make(map[string]C.ProxyAdapter)
}

func NewPacDynamic(option PacDynamicOption) *PacDynamic {
	return &PacDynamic{
		Base: &Base{
			name:  option.Name,
			addr:  "pac-dynamic",
			tp:    C.Http,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		proxyId: option.ProxyId,
		user:    option.UserName,
		pass:    option.Password,
		cache:   make(map[string]C.ProxyAdapter),
	}
}
