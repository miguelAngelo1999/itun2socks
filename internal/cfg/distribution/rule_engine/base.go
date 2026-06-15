package rule_engine

import (
	"errors"
	"slices"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/igoogolx/itun2socks/internal/constants"
)

type Rule interface {
	Match(value string) bool
	Value() string
	GetPolicy() constants.Policy
	Type() constants.RuleType
	Valid() bool
}

type Engine struct {
	rules []ParsedRule
	cache *lru.Cache[string, Rule]
}

var ErrNotFound = errors.New("not found")

// MatchWithProtocol evaluates the ordered rule list against a connection,
// applying the protocol filter (Requirement 3.4) before the type-specific
// match condition (Requirements 3.1-3.3).
//
// Rules are evaluated in declaration order (Requirements 4.1, 4.4).
// The first matching rule is returned (Requirement 4.2).
// If no rule matches, ErrNotFound is returned (Requirement 4.3).
//
// Protocol filtering:
//   - RuleProtocolAny  => evaluate regardless of connection protocol (backward compatible, Req 3.3)
//   - RuleProtocolTCP  => skip rule if conn protocol is not "tcp" (Req 3.1)
//   - RuleProtocolUDP  => skip rule if conn protocol is not "udp" (Req 3.2)
func (e *Engine) MatchWithProtocol(value string, types []constants.RuleType, protocol constants.RuleProtocol) (Rule, error) {
	// Check LRU cache only for protocol-agnostic lookups; protocol-specific
	// calls bypass the cache to guarantee correct per-protocol filtering.
	if protocol == constants.RuleProtocolAny {
		if cachedRule, ok := e.cache.Get(value); ok {
			return cachedRule, nil
		}
	}

	for _, parsed := range e.rules {
		// Step 1: Protocol filter -- skip rule if protocol does not match
		// the connection (Requirements 3.1, 3.2, 3.3, 3.4).
		if parsed.Protocol != constants.RuleProtocolAny {
			if parsed.Protocol == constants.RuleProtocolTCP && protocol != constants.RuleProtocolTCP {
				continue
			}
			if parsed.Protocol == constants.RuleProtocolUDP && protocol != constants.RuleProtocolUDP {
				continue
			}
		}

		// Step 2: Type filter -- only evaluate rules whose type is in the
		// requested set (preserves existing dispatch semantics).
		if !slices.Contains(types, parsed.Rule.Type()) {
			continue
		}

		// Step 3: Type-specific match condition.
		if parsed.Rule.Match(value) {
			if protocol == constants.RuleProtocolAny {
				e.cache.Add(value, parsed.Rule)
			}
			return parsed.Rule, nil
		}
	}
	return nil, ErrNotFound
}

// Match is the backward-compatible wrapper around MatchWithProtocol.
// It evaluates rules without protocol filtering (treats all rules as
// RuleProtocolAny), preserving pre-feature behaviour for callers that do
// not have connection-protocol information (e.g. DNS resolver).
func (e *Engine) Match(value string, types []constants.RuleType) (Rule, error) {
	return e.MatchWithProtocol(value, types, constants.RuleProtocolAny)
}

func (e *Engine) AddCache(value string, rule Rule) {
	e.cache.Add(value, rule)
}

func New(name string, extraRules []string) (*Engine, error) {
	rules, err := ParseToParsedRules(name, extraRules)
	if err != nil {
		return nil, err
	}
	cache, err := lru.New[string, Rule](1024)
	if err != nil {
		return nil, err
	}
	return &Engine{rules, cache}, nil
}
