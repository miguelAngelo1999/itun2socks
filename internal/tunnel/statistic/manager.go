package statistic

import (
	"time"

	"github.com/hashicorp/golang-lru/v2"
	"github.com/igoogolx/itun2socks/internal/constants"
	"github.com/igoogolx/itun2socks/pkg/log"
	"go.uber.org/atomic"
)

var DefaultManager *Manager

// Upper bound on tracked connections.
//
// This is a display and statistics view, not a connection owner, so the bound
// only caps memory. It was 256, which on a busy machine is exceeded routinely.
const maxTrackedConnections = 4096

// newManager builds a Manager whose connection cache never closes what it drops.
//
// The eviction callback used to call value.Close(), which was wrong twice over:
//
//   - Leave calls Remove, and golang-lru fires the eviction callback on Remove
//     just as it does on overflow, so every ordinary teardown closed the socket a
//     second time. That is the source of the constant "fail to close remote tcp
//     conn: use of closed network connection" noise.
//
//   - On overflow it terminated a connection that was still in use. A tracker's
//     LRU position is only refreshed when bytes move, in PushUploaded and
//     PushDownloaded, so a streaming response sitting idle between chunks drifts
//     to the tail. Once enough new connections arrive it is evicted and closed
//     mid-response. To the application the request simply hangs, with nothing
//     logged as an error.
//
// Connections are closed by whoever owns them, and that path calls Leave to stop
// tracking. Eviction now only forgets.
func newManager(size int) (*Manager, error) {
	cache, err := lru.NewWithEvict[string, tracker](size, func(key string, _ tracker) {
		log.Debugln("%s", log.FormatLog(log.CachePrefix, "stopped tracking connection "+key))
	})
	if err != nil {
		return nil, err
	}
	return &Manager{
		connections: cache,
		proxy:       newStatistic(),
		direct:      newStatistic(),
	}, nil
}

func newStatistic() *Statistic {
	return &Statistic{
		uploadTemp:    atomic.NewInt64(0),
		downloadTemp:  atomic.NewInt64(0),
		uploadBlip:    atomic.NewInt64(0),
		downloadBlip:  atomic.NewInt64(0),
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
	}
}

func init() {
	m, err := newManager(maxTrackedConnections)
	if err != nil {
		log.Fatalln(log.FormatLog(log.CachePrefix, "fail to init cache in statistic, err: %v"), err)
	}
	DefaultManager = m

	go DefaultManager.handle(constants.PolicyProxy)
	go DefaultManager.handle(constants.PolicyDirect)
}

type Statistic struct {
	uploadTemp    *atomic.Int64
	downloadTemp  *atomic.Int64
	uploadBlip    *atomic.Int64
	downloadBlip  *atomic.Int64
	uploadTotal   *atomic.Int64
	downloadTotal *atomic.Int64
}

type Manager struct {
	connections *lru.Cache[string, tracker]
	proxy       *Statistic
	direct      *Statistic
}

func (m *Manager) Join(c tracker) {
	m.connections.Add(c.ID(), c)
}

func (m *Manager) Leave(c tracker) {
	m.connections.Remove(c.ID())
}

func (m *Manager) getStatistic(rule constants.Policy) *Statistic {
	if rule == constants.PolicyProxy {
		return m.proxy
	}
	if rule == constants.PolicyDirect {
		return m.direct
	}
	return nil
}

func (m *Manager) PushUploaded(size int64, rule constants.Policy, t tracker) {
	m.connections.Get(t.ID())
	s := m.getStatistic(rule)
	if s != nil {
		s.uploadTemp.Add(size)
		s.uploadTotal.Add(size)
	}
}

func (m *Manager) PushDownloaded(size int64, rule constants.Policy, t tracker) {
	m.connections.Get(t.ID())
	s := m.getStatistic(rule)
	if s != nil {
		s.downloadTemp.Add(size)
		s.downloadTotal.Add(size)
	}
}

func (m *Manager) Now(rule constants.Policy) (up int64, down int64) {
	s := m.getStatistic(rule)
	if s != nil {
		return s.uploadBlip.Load(), s.downloadBlip.Load()
	}
	return 0, 0
}

func (m *Manager) Connections() []tracker {
	return m.connections.Values()
}

func (m *Manager) CloseAllConnections() {
	connections := m.Connections()
	for _, c := range connections {
		err := c.Close()
		if err != nil {
			log.Debugln(log.FormatLog(log.ExecutorPrefix, "fail to close connection, err: %v"), err)
		}
	}
}

func (m *Manager) GetTotal() *Total {

	return &Total{
		SnapshotStatistic{
			m.proxy.downloadTotal.Load(),
			m.proxy.uploadTotal.Load(),
		},
		SnapshotStatistic{
			m.direct.downloadTotal.Load(),
			m.direct.uploadTotal.Load(),
		},
	}
}

func (m *Manager) ResetStatistic(rule constants.Policy) {
	s := m.getStatistic(rule)
	if s != nil {
		s.uploadTemp.Store(0)
		s.uploadBlip.Store(0)
		s.uploadTotal.Store(0)
		s.downloadTemp.Store(0)
		s.downloadBlip.Store(0)
		s.downloadTotal.Store(0)
	}
}

func (m *Manager) handle(rule constants.Policy) {
	s := m.getStatistic(rule)
	if s == nil {
		return
	}
	ticker := time.NewTicker(time.Second)
	for range ticker.C {
		s.uploadBlip.Store(s.uploadTemp.Load())
		s.uploadTemp.Store(0)
		s.downloadBlip.Store(s.downloadTemp.Load())
		s.downloadTemp.Store(0)
	}
}

type SnapshotStatistic struct {
	DownloadTotal int64 `json:"download"`
	UploadTotal   int64 `json:"upload"`
}

type Total struct {
	Proxy  SnapshotStatistic `json:"proxy"`
	Direct SnapshotStatistic `json:"direct"`
}
