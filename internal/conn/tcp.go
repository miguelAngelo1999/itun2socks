package conn

import (
	"context"
	"net"
	"sync"

	"github.com/igoogolx/itun2socks/internal/balancer"
	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/pkg/clash/component/dialer"
	C "github.com/igoogolx/itun2socks/pkg/clash/constant"
	"github.com/igoogolx/itun2socks/pkg/log"
	"github.com/igoogolx/itun2socks/pkg/network_iface"
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
	connDialer, err := GetProxy(rule.GetPolicy())
	if err != nil {
		return nil, err
	}
	conn, dialErr := connDialer.DialContext(ctx, metadata, dialer.WithInterface(defaultInterface))
	if dialErr != nil && defaultInterface != "" {
		// Connection failed on the chosen interface — mark it unhealthy immediately
		// and retry with the other interface (instant failover).
		balancer.MarkUnhealthy(defaultInterface)
		balancer.Release(defaultInterface) // release the counter we incremented in Pick()
		fallbackIface := balancer.Pick()   // picks the next healthy interface
		if fallbackIface != "" && fallbackIface != defaultInterface {
			log.Debugln(log.FormatLog(log.TcpPrefix, "failover: %s → %s"), defaultInterface, fallbackIface)
			conn, dialErr = connDialer.DialContext(ctx, metadata, dialer.WithInterface(fallbackIface))
			if dialErr != nil {
				balancer.Release(fallbackIface)
			}
			return conn, dialErr
		}
		// No fallback available — try with no binding (OS default routing)
		conn, dialErr = connDialer.DialContext(ctx, metadata, dialer.WithInterface(network_iface.GetDefaultInterfaceName()))
		return conn, dialErr
	}
	return conn, dialErr
}
