package configuration

type Config struct {
	Proxy         []map[string]any  `json:"proxy"`
	Subscriptions []SubscriptionCfg `json:"subscriptions,omitempty"`
	Selected      struct {
		Proxy         string `json:"proxy"`
		Rule          string `json:"rule"`
		PreviousProxy string `json:"previousProxy,omitempty"`
	} `json:"selected"`
	Setting       SettingCfg       `json:"setting"`
	Rules         []string         `json:"rules"`
	SslInspection SslInspectionCfg `json:"sslInspection,omitempty"`
}

type SslInspectionCfg struct {
	Enabled        bool                 `json:"enabled"`
	InspectionList []SslInspectionEntry `json:"inspectionList,omitempty"`
}

type SslInspectionEntry struct {
	Pattern string `json:"pattern"`
	Enabled bool   `json:"enabled"`
}

type SubscriptionCfg struct {
	Id     string `json:"id"`
	Url    string `json:"url"`
	Name   string `json:"name"`
	Remark string `json:"remark"`
}

type SettingCfg struct {
	Mode             string `json:"mode"`
	DefaultInterface string `json:"defaultInterface"`
	LoadBalance      struct {
		Enabled    bool     `json:"enabled"`
		Interfaces []string `json:"interfaces"`
		Strategy   string   `json:"strategy"` // "least-conn" | "round-robin" | "failover"
	} `json:"loadBalance,omitempty"`
	LocalServer      `json:"localServer"`
	AutoMode         `json:"autoMode"`
	HijackDns        `json:"hijackDns"`
	Dns              struct {
		DisableCache bool `json:"disableCache"`
		Server       struct {
			Boost  []string `json:"boost"`
			Remote []string `json:"remote"`
			Local  []string `json:"local"`
		} `json:"server"`
		CustomizedOptions []string `json:"customizedOptions"`
		FakeIp            bool     `json:"fakeIp,omitempty"`
	} `json:"dns"`
	Language          string `json:"language,omitempty"`
	BlockQuic         bool   `json:"blockQuic,omitempty"`
	Stack             string `json:"stack"`
	ShouldFindProcess bool   `json:"shouldFindProcess,omitempty"`
	Theme             string `json:"theme,omitempty"`
	AutoConnect       bool   `json:"autoConnect,omitempty"`
	AutoLaunch        bool   `json:"autoLaunch,omitempty"`
	SensitiveInfoMode    bool   `json:"sensitiveInfoMode,omitempty"`
	RestoreAutoDetect    bool   `json:"restoreAutoDetect,omitempty"`
	// URLs used for connectivity testing — configurable so corporate networks
	// can point to an allowed domain instead of the default.
	HealthCheckUrl string `json:"healthCheckUrl,omitempty"` // used by /health watchdog
	DelayTestUrl   string `json:"delayTestUrl,omitempty"`   // used by /proxies/delay/:id
	// PacUrl is a manually-configured PAC/WPAD URL. When non-empty, lux fetches
	// this PAC file on startup and on every 30-min refresh cycle, and evaluates
	// FindProxyForURL per connection to route DIRECT traffic around the proxy.
	// Takes priority over auto-detected DHCP/registry PAC URLs.
	PacUrl string `json:"pacUrl,omitempty"`

	// BypassCidrs is a list of IP/CIDR ranges that should bypass the TUN interface
	// entirely at the routing table level. Traffic to these IPs never enters
	// lux_core's userspace stack — it goes directly out the physical adapter.
	// This is in addition to IP-CIDR,x,DIRECT rules (which are also auto-extracted).
	// Use for upstream proxy IPs, corporate subnets, etc.
	BypassCidrs []string `json:"bypassCidrs,omitempty"`

	// BypassProcesses is a list of process names/paths that should bypass the TUN.
	// On Windows: uses WFP (Windows Filtering Platform) permit filters so traffic
	// from these processes never enters the TUN interface.
	// On macOS: no kernel-level per-process bypass exists; these are handled by
	// the existing PROCESS,x,DIRECT rule engine after TUN capture.
	BypassProcesses []string `json:"bypassProcesses,omitempty"`
}

type DnsServer struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type LocalServer struct {
	Port     int  `json:"port"`
	AllowLan bool `json:"allowLan"`
}

type AutoMode struct {
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"`
	Url     string `json:"url"`
}

type HijackDns struct {
	Enabled        bool   `json:"enabled"`
	NetworkService string `json:"networkService"`
	AlwaysReset    bool   `json:"alwaysReset,omitempty"`
}
