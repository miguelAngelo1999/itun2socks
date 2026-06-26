package pac

import (
	"sync"

	"github.com/igoogolx/itun2socks/pkg/log"
)

// Manager holds the currently active PAC rules (injected on connect, cleared on disconnect).
var (
	activeRules []Rule
	activeMu    sync.RWMutex
	pacURL      string // the PAC URL for the current network (empty = none)
)

// GetActiveRules returns the currently injected PAC rules.
func GetActiveRules() []Rule {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return append([]Rule{}, activeRules...)
}

// GetPacURL returns the currently configured PAC URL.
func GetPacURL() string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return pacURL
}

// Apply fetches and parses the PAC URL, storing the resulting rules.
// Call this on connect when a PAC URL is detected.
// Returns the parsed rules (also stored internally).
func Apply(url string) ([]Rule, error) {
	if url == "" {
		Clear()
		return nil, nil
	}

	rules, err := FetchAndParse(url)
	if err != nil {
		log.Warnln("[pac] failed to fetch/parse PAC from %s: %v", url, err)
		return nil, err
	}

	activeMu.Lock()
	activeRules = rules
	pacURL = url
	activeMu.Unlock()

	log.Infoln("[pac] applied %d rules from %s", len(rules), url)
	return rules, nil
}

// Clear removes all active PAC rules (call on disconnect or network change).
func Clear() {
	activeMu.Lock()
	activeRules = nil
	pacURL = ""
	activeMu.Unlock()
	log.Infoln("[pac] cleared active PAC rules")
}

// GetDirectDomains returns just the DIRECT domain-suffix rules as strings
// for easy checking by the rule engine.
func GetDirectDomains() []string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	var domains []string
	for _, r := range activeRules {
		if r.Policy == "DIRECT" && (r.Type == "DOMAIN-SUFFIX" || r.Type == "DOMAIN") {
			domains = append(domains, r.Payload)
		}
	}
	return domains
}

// GetDirectCIDRs returns just the DIRECT IP-CIDR rules.
func GetDirectCIDRs() []string {
	activeMu.RLock()
	defer activeMu.RUnlock()
	var cidrs []string
	for _, r := range activeRules {
		if r.Policy == "DIRECT" && r.Type == "IP-CIDR" {
			cidrs = append(cidrs, r.Payload)
		}
	}
	return cidrs
}
