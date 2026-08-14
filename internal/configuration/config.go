package configuration

type Config struct {
	Proxy         []map[string]any  `json:"proxy"`
	Subscriptions []SubscriptionCfg `json:"subscriptions,omitempty"`
	Selected      struct {
		Proxy string `json:"proxy"`
		Rule  string `json:"rule"`
	} `json:"selected"`
	Setting SettingCfg `json:"setting"`

	// Rules is the legacy flat representation. It is regenerated on every write
	// from CustomizedRules so an older build downgraded onto this config still
	// finds a usable list, but it is never read once migration has run.
	//
	// Do not add features here. See rule_store.go.
	Rules []string `json:"rules"`

	// CustomizedRules is the authoritative rule store.
	CustomizedRules []RuleItem `json:"customizedRules,omitempty"`

	// RuleGroups organise rules for display. They do not affect matching
	// semantics beyond determining the order in which rules are flattened.
	RuleGroups []RuleGroup `json:"ruleGroups,omitempty"`

	// NextRuleId is the monotonic source of rule ids. It is persisted rather
	// than derived from the existing rules, because deriving max+1 would let a
	// deleted rule's id be handed out again, silently retargeting anything that
	// still referenced it.
	NextRuleId int `json:"nextRuleId,omitempty"`

	// NextGroupId serves the same purpose for groups.
	NextGroupId int `json:"nextGroupId,omitempty"`

	// SelectedRuleset names the built-in ruleset in use, e.g. "proxy_all".
	// Previously this was stored inside Rules as a comma-free entry, which
	// forced the engine to distinguish rules from ruleset names by looking for
	// a comma.
	SelectedRuleset string `json:"selectedRuleset,omitempty"`

	// QuarantinedRules holds legacy entries that could not be parsed during
	// migration. They are kept verbatim so nothing is lost, and surfaced rather
	// than discarded.
	QuarantinedRules []string `json:"quarantinedRules,omitempty"`
}

// RuleGroup is a display grouping for rules. Groups do not nest.
type RuleGroup struct {
	Id      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Order   int    `json:"order"`
}

// RuleCondition is one match criterion. A rule holds at least one; all of a
// rule's conditions must match for the rule to match.
type RuleCondition struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// RulePolicy is a rule's outcome.
//
// Kind is one of "direct", "reject", "selected" or "proxy". ProxyId is set only
// when Kind is "proxy" and holds the target proxy's id.
//
// This is a tagged form rather than a bare string because a bare string cannot
// distinguish the built-in policy PROXY from a proxy profile that happens to be
// named "Proxy" — which is exactly how two rules in the wild became silently
// unmatchable after the proxy they referenced was deleted.
type RulePolicy struct {
	Kind    string `json:"kind"`
	ProxyId string `json:"proxyId,omitempty"`
}

const (
	PolicyKindDirect   = "direct"
	PolicyKindReject   = "reject"
	PolicyKindSelected = "selected"
	PolicyKindProxy    = "proxy"
)

// RuleItem is a single customized rule.
type RuleItem struct {
	// Id is opaque, assigned once, and never reused. Every mutation targets it.
	Id string `json:"id"`

	// Slug is derived from the rule's content for logs and tooltips. It is
	// regenerated whenever the content changes, so it cannot go stale, and it is
	// never accepted as the target of a mutation.
	Slug string `json:"slug"`

	// GroupId is empty for rules in the implicit default group.
	GroupId string `json:"groupId,omitempty"`

	Conditions []RuleCondition `json:"conditions"`
	Policy     RulePolicy      `json:"policy"`

	// Network restricts the rule to one transport: "", "tcp" or "udp".
	Network string `json:"network,omitempty"`

	Enabled bool `json:"enabled"`
	Order   int  `json:"order"`

	// Broken is set at load time when the rule cannot be applied, most often
	// because the proxy it targets no longer exists. A broken rule is retained
	// and surfaced, never silently dropped and never allowed to fall through to
	// a different policy.
	Broken string `json:"broken,omitempty"`
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
	SensitiveInfoMode bool   `json:"sensitiveInfoMode,omitempty"`

	PacUrl          string   `json:"pacUrl,omitempty"`
	BypassCidrs     []string `json:"bypassCidrs,omitempty"`
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
