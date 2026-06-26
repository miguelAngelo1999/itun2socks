// Package pac parses PAC (Proxy Auto-Config) files and extracts routing rules
// that can be injected into Lux's rule engine as temporary DIRECT rules.
//
// Handles common PAC functions without a full JS engine:
//   - dnsDomainIs(host, ".example.com") → DOMAIN-SUFFIX
//   - shExpMatch(host, "*.example.com") → DOMAIN-SUFFIX
//   - isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") → IP-CIDR
//   - isPlainHostName(host) → skipped (OS handles)
//   - isInNet(myIpAddress(), ...) → skipped (subnet detection)
//
// The parser is intentionally simple — it uses regex to extract patterns from
// the JavaScript source without evaluating it. This covers ~95% of real-world
// corporate PAC files which use straightforward if/return structures.
package pac

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/igoogolx/itun2socks/pkg/log"
)

// Rule represents a single extracted routing rule from a PAC file.
type Rule struct {
	Type    string // "DOMAIN-SUFFIX", "DOMAIN", "IP-CIDR"
	Payload string // e.g. "example.com", "10.0.0.0/8"
	Policy  string // "DIRECT" or "PROXY"
}

// String formats the rule in Lux rule syntax.
func (r Rule) String() string {
	return fmt.Sprintf("%s,%s,%s", r.Type, r.Payload, r.Policy)
}

// FetchAndParse downloads a PAC file from the given URL and parses it into rules.
func FetchAndParse(pacURL string) ([]Rule, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// Bypass system proxy for PAC fetch — PAC tells us what the proxy is
			Proxy: nil,
		},
	}
	resp, err := client.Get(pacURL)
	if err != nil {
		return nil, fmt.Errorf("fetch PAC: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read PAC body: %w", err)
	}

	return Parse(string(body))
}

// Parse extracts routing rules from PAC JavaScript source code.
func Parse(js string) ([]Rule, error) {
	var rules []Rule
	seen := make(map[string]bool) // deduplicate

	// Extract dnsDomainIs patterns: dnsDomainIs(host, "example.com")
	dnsDomainRe := regexp.MustCompile(`dnsDomainIs\s*\(\s*host\s*,\s*"([^"]+)"\s*\)`)
	// Extract shExpMatch patterns: shExpMatch(host, "*.example.com") or shExpMatch(host, "(*.inet)")
	shExpRe := regexp.MustCompile(`shExpMatch\s*\(\s*host\s*,\s*"([^"]+)"\s*\)`)
	// Extract isInNet with dnsResolve: isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")
	isInNetHostRe := regexp.MustCompile(`isInNet\s*\(\s*dnsResolve\s*\(\s*host\s*\)\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)`)

	// Split into blocks: each "return" statement belongs to the preceding conditions
	// We look for patterns in if-blocks that precede "return DIRECT" or "return PROXY"
	lines := strings.Split(js, "\n")

	// Track which return statement follows each condition block
	type condBlock struct {
		conditions []string
		returnStmt string
	}

	var blocks []condBlock
	var currentConds []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Collect condition lines
		if strings.Contains(trimmed, "dnsDomainIs") ||
			strings.Contains(trimmed, "shExpMatch") ||
			strings.Contains(trimmed, "isInNet") ||
			strings.Contains(trimmed, "isPlainHostName") {
			currentConds = append(currentConds, trimmed)
		}

		// When we hit a return, associate accumulated conditions with the policy
		if strings.Contains(trimmed, "return") && (strings.Contains(trimmed, "DIRECT") || strings.Contains(trimmed, "PROXY")) {
			policy := "PROXY"
			if strings.Contains(trimmed, "DIRECT") {
				policy = "DIRECT"
			}
			if len(currentConds) > 0 {
				blocks = append(blocks, condBlock{
					conditions: append([]string{}, currentConds...),
					returnStmt: policy,
				})
			}
			currentConds = nil
		}
	}

	// Process each block
	for _, block := range blocks {
		for _, cond := range block.conditions {
			// Skip myIpAddress() checks — they're subnet detection, not routing
			if strings.Contains(cond, "myIpAddress()") {
				continue
			}

			// dnsDomainIs
			for _, match := range dnsDomainRe.FindAllStringSubmatch(cond, -1) {
				domain := strings.TrimPrefix(match[1], ".")
				domain = strings.TrimPrefix(domain, "*.")
				key := fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", domain, block.returnStmt)
				if !seen[key] {
					seen[key] = true
					rules = append(rules, Rule{
						Type:    "DOMAIN-SUFFIX",
						Payload: domain,
						Policy:  block.returnStmt,
					})
				}
			}

			// shExpMatch
			for _, match := range shExpRe.FindAllStringSubmatch(cond, -1) {
				pattern := match[1]
				// Remove wrapping parens: "(*.inet)" → "*.inet"
				pattern = strings.Trim(pattern, "()")
				// Convert shell pattern to domain suffix
				if strings.HasPrefix(pattern, "*.") {
					suffix := strings.TrimPrefix(pattern, "*.")
					key := fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", suffix, block.returnStmt)
					if !seen[key] {
						seen[key] = true
						rules = append(rules, Rule{
							Type:    "DOMAIN-SUFFIX",
							Payload: suffix,
							Policy:  block.returnStmt,
						})
					}
				} else if strings.HasPrefix(pattern, "*") {
					suffix := strings.TrimPrefix(pattern, "*")
					key := fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", suffix, block.returnStmt)
					if !seen[key] {
						seen[key] = true
						rules = append(rules, Rule{
							Type:    "DOMAIN-SUFFIX",
							Payload: suffix,
							Policy:  block.returnStmt,
						})
					}
				}
			}

			// isInNet(dnsResolve(host), ...)
			for _, match := range isInNetHostRe.FindAllStringSubmatch(cond, -1) {
				network := match[1]
				mask := match[2]
				cidr := maskToCIDR(network, mask)
				if cidr != "" {
					key := fmt.Sprintf("IP-CIDR,%s,%s", cidr, block.returnStmt)
					if !seen[key] {
						seen[key] = true
						rules = append(rules, Rule{
							Type:    "IP-CIDR",
							Payload: cidr,
							Policy:  block.returnStmt,
						})
					}
				}
			}

			// Plain IP in dnsDomainIs (e.g. dnsDomainIs(host, "191.241.241.251"))
			for _, match := range dnsDomainRe.FindAllStringSubmatch(cond, -1) {
				val := match[1]
				if ip := net.ParseIP(val); ip != nil {
					cidr := val + "/32"
					key := fmt.Sprintf("IP-CIDR,%s,%s", cidr, block.returnStmt)
					if !seen[key] {
						seen[key] = true
						rules = append(rules, Rule{
							Type:    "IP-CIDR",
							Payload: cidr,
							Policy:  block.returnStmt,
						})
					}
				}
			}
		}
	}

	log.Infoln("[pac] parsed %d rules from PAC file", len(rules))
	return rules, nil
}

// maskToCIDR converts "10.0.0.0" + "255.0.0.0" → "10.0.0.0/8"
func maskToCIDR(network, mask string) string {
	ip := net.ParseIP(network)
	if ip == nil {
		return ""
	}
	m := net.ParseIP(mask)
	if m == nil {
		return ""
	}
	m4 := m.To4()
	if m4 == nil {
		return ""
	}
	ones, _ := net.IPMask(m4).Size()
	if ones == 0 {
		return ""
	}
	return fmt.Sprintf("%s/%d", network, ones)
}
