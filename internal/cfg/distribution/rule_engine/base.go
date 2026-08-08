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

// MatchWithProtocol evaluates rules in declaration order and returns the first
// match, applying each rule's protocol restriction before its own condition.
//
// Results are cached only for protocol-agnostic lookups. A protocol-scoped
// lookup must not populate or read that cache, or a TCP-only rule matched once
// would be served back for the same host over UDP.
func (e *Engine) MatchWithProtocol(value string, types []constants.RuleType, protocol constants.RuleProtocol) (Rule, error) {
	if protocol == constants.RuleProtocolAny {
		if cached, ok := e.cache.Get(value); ok {
			return cached, nil
		}
	}

	for _, parsed := range e.rules {
		if !parsed.appliesTo(protocol) {
			continue
		}
		if !slices.Contains(types, parsed.Rule.Type()) {
			continue
		}
		if parsed.Rule.Match(value) {
			if protocol == constants.RuleProtocolAny {
				e.cache.Add(value, parsed.Rule)
			}
			return parsed.Rule, nil
		}
	}
	return nil, ErrNotFound
}

// Match evaluates without protocol information, for callers that have none.
func (e *Engine) Match(value string, types []constants.RuleType) (Rule, error) {
	return e.MatchWithProtocol(value, types, constants.RuleProtocolAny)
}

func (e *Engine) AddCache(value string, rule Rule) {
	e.cache.Add(value, rule)
}

// Rules exposes the parsed rules in evaluation order, for diagnostics.
func (e *Engine) Rules() []ParsedRule {
	out := make([]ParsedRule, len(e.rules))
	copy(out, e.rules)
	return out
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

// NewWithPolicies builds an engine that also accepts policies naming a specific
// proxy. knownProxyIds lists the ids a rule may legitimately target; a rule
// naming anything else is dropped, as before.
func NewWithPolicies(name string, extraRules []string, knownProxyIds []string) (*Engine, error) {
	rules, err := parseToParsedRules(name, extraRules, knownProxyIds)
	if err != nil {
		return nil, err
	}
	cache, err := lru.New[string, Rule](1024)
	if err != nil {
		return nil, err
	}
	return &Engine{rules, cache}, nil
}
