package statistic

import (
	"net"
	"time"

	"github.com/igoogolx/itun2socks/internal/cfg/distribution/rule_engine"
	"github.com/igoogolx/itun2socks/internal/conn"
	"github.com/igoogolx/itun2socks/internal/dns"

	C "github.com/igoogolx/itun2socks/pkg/clash/constant"

	"github.com/gofrs/uuid/v5"
	"go.uber.org/atomic"
)

type tracker interface {
	ID() string
	Close() error
}

type trackerInfo struct {
	UUID          uuid.UUID        `json:"id"`
	Metadata      *C.Metadata      `json:"metadata"`
	UploadTotal   *atomic.Int64    `json:"upload"`
	DownloadTotal *atomic.Int64    `json:"download"`
	Start         int64            `json:"start"`
	Rule          rule_engine.Rule `json:"rule"`
	Domain        string           `json:"domain"`
}

type TcpTracker struct {
	net.Conn `json:"-"`
	*trackerInfo
	manager *Manager
}

func (tt *TcpTracker) ID() string {
	return tt.UUID.String()
}

func (tt *TcpTracker) Read(b []byte) (int, error) {
	n, err := tt.Conn.Read(b)
	download := int64(n)
	tt.manager.PushDownloaded(download, tt.Rule.GetPolicy(), tt)
	tt.DownloadTotal.Add(download)
	return n, err
}

func (tt *TcpTracker) Write(b []byte) (int, error) {
	n, err := tt.Conn.Write(b)
	upload := int64(n)
	tt.manager.PushUploaded(upload, tt.Rule.GetPolicy(), tt)
	tt.UploadTotal.Add(upload)
	return n, err
}

func (tt *TcpTracker) Close() error {
	tt.manager.Leave(tt)
	return tt.Conn.Close()
}

// CloseWrite forwards a half-close to the connection underneath.
//
// The embedded field is a net.Conn, whose method set has no CloseWrite, so
// wrapping a connection in a tracker used to hide the capability. The relay tests
// for it with an interface assertion and silently falls back to a full close when
// it is absent, which turns "I have finished sending" into "I have hung up" and
// cuts off a response that was still arriving.
func (tt *TcpTracker) CloseWrite() error {
	if cw, ok := tt.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	// Nothing to forward to. Report success rather than closing the whole
	// connection, which is what the caller would do with an error.
	return nil
}

func NewTCPTracker(conn net.Conn, manager *Manager, metadata *C.Metadata, rule rule_engine.Rule) *TcpTracker {
	uid, _ := uuid.NewV4()

	t := &TcpTracker{
		Conn:    conn,
		manager: manager,
		trackerInfo: &trackerInfo{
			UUID:          uid,
			Start:         time.Now().UnixNano() / int64(time.Millisecond),
			Metadata:      metadata,
			Rule:          rule,
			UploadTotal:   atomic.NewInt64(0),
			DownloadTotal: atomic.NewInt64(0),
		},
	}

	if cachedDomain, ok := dns.GetCachedDnsItem(metadata.DstIP.String()); ok {
		t.trackerInfo.Domain = cachedDomain
	} else if metadata.Host != "" {
		t.trackerInfo.Domain = metadata.Host
	} else {
		t.trackerInfo.Domain = "unknown"
	}
	manager.Join(t)
	return t
}

type UdpTracker struct {
	conn.CopyablePacketConn `json:"-"`
	*trackerInfo
	manager *Manager
}

func (ut *UdpTracker) ID() string {
	return ut.UUID.String()
}

func (ut *UdpTracker) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := ut.PacketConn.ReadFrom(b)
	download := int64(n)
	ut.manager.PushDownloaded(download, ut.Rule.GetPolicy(), ut)
	ut.DownloadTotal.Add(download)
	return n, addr, err
}

func (ut *UdpTracker) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := ut.PacketConn.WriteTo(b, addr)
	upload := int64(n)
	ut.manager.PushUploaded(upload, ut.Rule.GetPolicy(), ut)
	ut.UploadTotal.Add(upload)
	return n, err
}

func (ut *UdpTracker) Close() error {
	ut.manager.Leave(ut)
	return ut.PacketConn.Close()
}

func NewUDPTracker(conn conn.CopyablePacketConn, manager *Manager, metadata *C.Metadata, rule rule_engine.Rule) *UdpTracker {
	uid, _ := uuid.NewV4()

	ut := &UdpTracker{
		CopyablePacketConn: conn,
		manager:            manager,
		trackerInfo: &trackerInfo{
			UUID:          uid,
			Start:         time.Now().UnixNano() / int64(time.Millisecond),
			Metadata:      metadata,
			Rule:          rule,
			UploadTotal:   atomic.NewInt64(0),
			DownloadTotal: atomic.NewInt64(0),
		},
	}

	if cachedDomain, ok := dns.GetCachedDnsItem(metadata.DstIP.String()); ok {
		ut.trackerInfo.Domain = cachedDomain
	} else if metadata.Host != "" {
		ut.trackerInfo.Domain = metadata.Host
	} else {
		ut.trackerInfo.Domain = "unknown"
	}

	manager.Join(ut)
	return ut
}
