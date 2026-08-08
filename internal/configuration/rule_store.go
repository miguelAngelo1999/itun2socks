package configuration

// Rule storage keyed by opaque id.
//
// The previous representation was a flat []string in which the string served as
// both the rule definition and its identity, with disabled state encoded as a
// leading "#". Because the prefix altered the string, toggling a rule altered
// its identity, which broke every operation that matched by string equality:
// deleting a disabled rule could not find it, the same rule could exist twice in
// enabled and disabled form, and reordering rebuilt the array from whatever the
// client sent, silently dropping anything omitted.
//
// Here identity is an opaque id, state is a boolean, and match criteria are a
// list of conditions.

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/igoogolx/itun2socks/internal/constants"
)

var (
	ErrRuleNotFound  = errors.New("rule not found")
	ErrGroupNotFound = errors.New("rule group not found")
	ErrDuplicateRule = errors.New("a rule with the same conditions and policy already exists")
	ErrNoConditions  = errors.New("a rule needs at least one condition")
)

// DefaultGroupId is the sentinel for rules that belong to no explicit group.
// They are evaluated after every named group.
const DefaultGroupId = ""

// ── Reads ───────────────────────────────────────────────────────────────────

func GetRules() ([]RuleItem, error) {
	c, err := Read()
	if err != nil {
		return nil, err
	}
	return c.CustomizedRules, nil
}

func GetRuleGroups() ([]RuleGroup, error) {
	c, err := Read()
	if err != nil {
		return nil, err
	}
	return c.RuleGroups, nil
}

func GetRule(id string) (RuleItem, error) {
	rules, err := GetRules()
	if err != nil {
		return RuleItem{}, err
	}
	for _, r := range rules {
		if r.Id == id {
			return r, nil
		}
	}
	return RuleItem{}, ErrRuleNotFound
}

// EffectiveRules returns the rules to evaluate, in evaluation order.
//
// Groups are flattened in group order, then rules in rule order within each
// group, with the implicit default group last. Rules that are disabled, that
// belong to a disabled group, or that are broken are excluded.
//
// Disabling a group excludes its rules without touching each rule's own Enabled
// flag, so re-enabling the group restores exactly the previous state.
func EffectiveRules() ([]RuleItem, error) {
	c, err := Read()
	if err != nil {
		return nil, err
	}
	return effectiveFrom(c), nil
}

func effectiveFrom(c Config) []RuleItem {
	groups := make([]RuleGroup, len(c.RuleGroups))
	copy(groups, c.RuleGroups)
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Order < groups[j].Order })

	var out []RuleItem
	emit := func(groupId string) {
		var rs []RuleItem
		for _, r := range c.CustomizedRules {
			if r.GroupId != groupId {
				continue
			}
			if !r.Enabled || r.Broken != "" {
				continue
			}
			rs = append(rs, r)
		}
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].Order < rs[j].Order })
		out = append(out, rs...)
	}

	for _, g := range groups {
		if !g.Enabled {
			continue
		}
		emit(g.Id)
	}
	emit(DefaultGroupId)
	return out
}

// ── Rendering ───────────────────────────────────────────────────────────────

// RawValue renders a rule in the engine's textual form.
//
// Disabled state is never encoded here: EffectiveRules has already excluded
// disabled rules, so a "#" prefix would be meaningless. That prefix is what
// made the old representation ambiguous.
func (r RuleItem) RawValue() string {
	if len(r.Conditions) == 0 {
		return ""
	}
	c := r.Conditions[0]
	parts := []string{c.Type, c.Value, string(r.PolicyValue())}
	if r.Network != "" {
		parts = append(parts, r.Network)
	}
	return strings.Join(parts, ",")
}

// PolicyValue maps a RulePolicy onto the engine's Policy type. A rule targeting
// a specific proxy yields that proxy's id.
func (r RuleItem) PolicyValue() constants.Policy {
	switch r.Policy.Kind {
	case PolicyKindDirect:
		return constants.PolicyDirect
	case PolicyKindReject:
		return constants.PolicyReject
	case PolicyKindProxy:
		return constants.Policy(r.Policy.ProxyId)
	default:
		return constants.PolicyProxy
	}
}

// PolicyLabel is the human-readable policy, resolving a proxy id to its current
// display name so a renamed proxy reads correctly everywhere.
func PolicyLabel(p RulePolicy, c Config) string {
	switch p.Kind {
	case PolicyKindDirect:
		return "DIRECT"
	case PolicyKindReject:
		return "REJECT"
	case PolicyKindProxy:
		if name := proxyNameById(c, p.ProxyId); name != "" {
			return name
		}
		return "<missing proxy>"
	default:
		return "PROXY"
	}
}

func proxyNameById(c Config, id string) string {
	for _, p := range c.Proxy {
		if fmt.Sprint(p["id"]) == id {
			return fmt.Sprint(p["name"])
		}
	}
	return ""
}

func proxyIdByName(c Config, name string) string {
	for _, p := range c.Proxy {
		if fmt.Sprint(p["name"]) == name {
			return fmt.Sprint(p["id"])
		}
	}
	return ""
}

// ── Slugs ───────────────────────────────────────────────────────────────────

var slugReplacer = strings.NewReplacer(
	".", "-", "/", "-", ":", "-", ";", "-", ",", "-",
	" ", "-", "_", "-", "*", "", "?", "", "\\", "-",
)

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = slugReplacer.Replace(s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}

// makeSlug builds a readable label from every condition plus the policy, so a
// compound rule stays identifiable in logs.
func makeSlug(r RuleItem, c Config) string {
	parts := make([]string, 0, len(r.Conditions)*2+1)
	for _, cond := range r.Conditions {
		parts = append(parts, slugify(cond.Type), slugify(cond.Value))
	}
	parts = append(parts, slugify(PolicyLabel(r.Policy, c)))
	if r.Network != "" {
		parts = append(parts, slugify(r.Network))
	}
	return strings.Join(parts, "-")
}

// uniqueSlug appends a numeric disambiguator when needed. Requirement 3 makes
// exact content duplicates impossible, so this only triggers for values that
// normalise to the same slug.
func uniqueSlug(base string, taken map[string]bool) string {
	if !taken[base] {
		return base
	}
	for i := 2; ; i++ {
		candidate := base + "-" + strconv.Itoa(i)
		if !taken[candidate] {
			return candidate
		}
	}
}

func slugsInUse(c Config, exceptId string) map[string]bool {
	taken := make(map[string]bool, len(c.CustomizedRules))
	for _, r := range c.CustomizedRules {
		if r.Id == exceptId {
			continue
		}
		taken[r.Slug] = true
	}
	return taken
}

// ── Identity ────────────────────────────────────────────────────────────────

func nextRuleId(c *Config) string {
	if c.NextRuleId < 1 {
		c.NextRuleId = 1
	}
	id := "r" + strconv.Itoa(c.NextRuleId)
	c.NextRuleId++
	return id
}

func nextGroupId(c *Config) string {
	if c.NextGroupId < 1 {
		c.NextGroupId = 1
	}
	id := "g" + strconv.Itoa(c.NextGroupId)
	c.NextGroupId++
	return id
}

// ── Duplicate detection ─────────────────────────────────────────────────────

// conditionKey is the identity used for duplicate detection: the conditions,
// the policy and the protocol. Enabled state is deliberately excluded, so an
// enabled and a disabled copy of the same rule are duplicates. Under the old
// representation they were distinct strings and both survived.
func conditionKey(r RuleItem) string {
	cs := make([]string, 0, len(r.Conditions))
	for _, c := range r.Conditions {
		cs = append(cs, strings.ToLower(c.Type)+"="+c.Value)
	}
	sort.Strings(cs)
	return strings.Join(cs, "&") + "|" + r.Policy.Kind + ":" + r.Policy.ProxyId + "|" + r.Network
}

func findDuplicate(c Config, candidate RuleItem, exceptId string) (RuleItem, bool) {
	key := conditionKey(candidate)
	for _, r := range c.CustomizedRules {
		if r.Id == exceptId {
			continue
		}
		if conditionKey(r) == key {
			return r, true
		}
	}
	return RuleItem{}, false
}

// ── Validation ──────────────────────────────────────────────────────────────

func validate(c Config, r RuleItem) error {
	if len(r.Conditions) == 0 {
		return ErrNoConditions
	}
	for _, cond := range r.Conditions {
		if strings.TrimSpace(cond.Type) == "" || strings.TrimSpace(cond.Value) == "" {
			return fmt.Errorf("condition needs a type and a value")
		}
	}
	switch r.Policy.Kind {
	case PolicyKindDirect, PolicyKindReject, PolicyKindSelected:
	case PolicyKindProxy:
		if r.Policy.ProxyId == "" {
			return fmt.Errorf("policy targets a proxy but no proxy id was given")
		}
		if proxyNameById(c, r.Policy.ProxyId) == "" {
			return fmt.Errorf("policy targets proxy %q, which does not exist", r.Policy.ProxyId)
		}
	default:
		return fmt.Errorf("unknown policy kind %q", r.Policy.Kind)
	}
	return nil
}

// markBroken flags rules whose target proxy has disappeared.
//
// Such a rule is kept and reported rather than deleted, and is excluded from
// evaluation so it cannot quietly fall through to a different policy. Deleting a
// proxy previously left its rules in place with no indication they had stopped
// working.
func markBroken(c *Config) {
	for i := range c.CustomizedRules {
		r := &c.CustomizedRules[i]
		if r.Policy.Kind != PolicyKindProxy {
			r.Broken = ""
			continue
		}
		if proxyNameById(*c, r.Policy.ProxyId) == "" {
			r.Broken = fmt.Sprintf("proxy %q no longer exists", r.Policy.ProxyId)
		} else {
			r.Broken = ""
		}
	}
}

// ── Mutations ───────────────────────────────────────────────────────────────

func CreateRule(in RuleItem) (RuleItem, error) {
	c, err := Read()
	if err != nil {
		return RuleItem{}, err
	}
	if err := validate(c, in); err != nil {
		return RuleItem{}, err
	}
	if dup, found := findDuplicate(c, in, ""); found {
		return RuleItem{}, fmt.Errorf("%w: %s", ErrDuplicateRule, dup.Slug)
	}

	in.Id = nextRuleId(&c)
	in.Slug = uniqueSlug(makeSlug(in, c), slugsInUse(c, ""))
	in.Order = maxOrderInGroup(c, in.GroupId) + 1
	in.Broken = ""

	c.CustomizedRules = append(c.CustomizedRules, in)
	syncLegacyRules(&c)
	if err := Write(c); err != nil {
		return RuleItem{}, err
	}
	return in, nil
}

func UpdateRule(id string, in RuleItem) error {
	c, err := Read()
	if err != nil {
		return err
	}
	idx := indexOfRule(c, id)
	if idx < 0 {
		return ErrRuleNotFound
	}
	if err := validate(c, in); err != nil {
		return err
	}
	if dup, found := findDuplicate(c, in, id); found {
		return fmt.Errorf("%w: %s", ErrDuplicateRule, dup.Slug)
	}

	existing := c.CustomizedRules[idx]

	// Identity, position and group membership are not editable through this
	// path; only the rule's content is. Preserving Id is the whole point.
	in.Id = existing.Id
	in.Order = existing.Order
	in.GroupId = existing.GroupId
	in.Slug = uniqueSlug(makeSlug(in, c), slugsInUse(c, id))

	c.CustomizedRules[idx] = in
	markBroken(&c)
	syncLegacyRules(&c)
	return Write(c)
}

// DeleteRule removes rules by id.
//
// No parsing and no string comparison, so a disabled rule deletes exactly like
// an enabled one. The old implementation validated the incoming string before
// matching, which rejected the "#" prefix and made deleting a disabled rule
// impossible.
func DeleteRule(ids []string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	kept := make([]RuleItem, 0, len(c.CustomizedRules))
	removed := 0
	for _, r := range c.CustomizedRules {
		if want[r.Id] {
			removed++
			continue
		}
		kept = append(kept, r)
	}
	if removed != len(want) {
		return ErrRuleNotFound
	}
	c.CustomizedRules = kept
	syncLegacyRules(&c)
	return Write(c)
}

// ToggleRule flips a rule's enabled flag. Identity is untouched.
func ToggleRule(id string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	idx := indexOfRule(c, id)
	if idx < 0 {
		return ErrRuleNotFound
	}
	c.CustomizedRules[idx].Enabled = !c.CustomizedRules[idx].Enabled
	syncLegacyRules(&c)
	return Write(c)
}

// SetRuleEnabled sets the flag explicitly, for callers that know the state they
// want rather than wanting to invert it.
func SetRuleEnabled(id string, enabled bool) error {
	c, err := Read()
	if err != nil {
		return err
	}
	idx := indexOfRule(c, id)
	if idx < 0 {
		return ErrRuleNotFound
	}
	c.CustomizedRules[idx].Enabled = enabled
	syncLegacyRules(&c)
	return Write(c)
}

// ReorderRules applies a new order to one group.
//
// Rules whose ids are absent from the request keep their prior relative order
// and follow the named ones; unknown ids are ignored. The old implementation
// replaced the whole array with the client's payload, so a filtered or stale
// client list silently deleted rules.
func ReorderRules(groupId string, ids []string) error {
	c, err := Read()
	if err != nil {
		return err
	}

	pos := make(map[string]int, len(ids))
	for i, id := range ids {
		pos[id] = i
	}

	var inGroup, others []RuleItem
	for _, r := range c.CustomizedRules {
		if r.GroupId == groupId {
			inGroup = append(inGroup, r)
		} else {
			others = append(others, r)
		}
	}

	sort.SliceStable(inGroup, func(i, j int) bool {
		pi, iok := pos[inGroup[i].Id]
		pj, jok := pos[inGroup[j].Id]
		switch {
		case iok && jok:
			return pi < pj
		case iok:
			return true
		case jok:
			return false
		default:
			// Neither was named: SliceStable preserves their existing order.
			return false
		}
	})

	for i := range inGroup {
		inGroup[i].Order = i
	}

	c.CustomizedRules = append(others, inGroup...)
	syncLegacyRules(&c)
	return Write(c)
}

func MoveRuleToGroup(ruleId, groupId string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	idx := indexOfRule(c, ruleId)
	if idx < 0 {
		return ErrRuleNotFound
	}
	if groupId != DefaultGroupId && indexOfGroup(c, groupId) < 0 {
		return ErrGroupNotFound
	}
	c.CustomizedRules[idx].GroupId = groupId
	c.CustomizedRules[idx].Order = maxOrderInGroup(c, groupId) + 1
	syncLegacyRules(&c)
	return Write(c)
}

// ── Groups ──────────────────────────────────────────────────────────────────

func CreateGroup(name string) (RuleGroup, error) {
	c, err := Read()
	if err != nil {
		return RuleGroup{}, err
	}
	g := RuleGroup{
		Id:      nextGroupId(&c),
		Name:    strings.TrimSpace(name),
		Enabled: true,
		Order:   len(c.RuleGroups),
	}
	if g.Name == "" {
		return RuleGroup{}, fmt.Errorf("group needs a name")
	}
	c.RuleGroups = append(c.RuleGroups, g)
	return g, Write(c)
}

func RenameGroup(id, name string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	idx := indexOfGroup(c, id)
	if idx < 0 {
		return ErrGroupNotFound
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("group needs a name")
	}
	c.RuleGroups[idx].Name = strings.TrimSpace(name)
	return Write(c)
}

func ToggleGroup(id string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	idx := indexOfGroup(c, id)
	if idx < 0 {
		return ErrGroupNotFound
	}
	c.RuleGroups[idx].Enabled = !c.RuleGroups[idx].Enabled
	syncLegacyRules(&c)
	return Write(c)
}

// DeleteGroup removes a group and moves its rules to the default group. Rules
// are never deleted as a side effect of deleting their container.
func DeleteGroup(id string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	idx := indexOfGroup(c, id)
	if idx < 0 {
		return ErrGroupNotFound
	}
	c.RuleGroups = append(c.RuleGroups[:idx], c.RuleGroups[idx+1:]...)
	for i := range c.CustomizedRules {
		if c.CustomizedRules[i].GroupId == id {
			c.CustomizedRules[i].GroupId = DefaultGroupId
		}
	}
	for i := range c.RuleGroups {
		c.RuleGroups[i].Order = i
	}
	syncLegacyRules(&c)
	return Write(c)
}

func ReorderGroups(ids []string) error {
	c, err := Read()
	if err != nil {
		return err
	}
	pos := make(map[string]int, len(ids))
	for i, id := range ids {
		pos[id] = i
	}
	sort.SliceStable(c.RuleGroups, func(i, j int) bool {
		pi, iok := pos[c.RuleGroups[i].Id]
		pj, jok := pos[c.RuleGroups[j].Id]
		switch {
		case iok && jok:
			return pi < pj
		case iok:
			return true
		case jok:
			return false
		default:
			return false
		}
	})
	for i := range c.RuleGroups {
		c.RuleGroups[i].Order = i
	}
	syncLegacyRules(&c)
	return Write(c)
}

// ── Proxy deletion impact ───────────────────────────────────────────────────

// RulesTargetingProxy reports which rules reference a proxy, so deleting it can
// say what will break instead of silently orphaning them.
func RulesTargetingProxy(proxyId string) ([]RuleItem, error) {
	rules, err := GetRules()
	if err != nil {
		return nil, err
	}
	var out []RuleItem
	for _, r := range rules {
		if r.Policy.Kind == PolicyKindProxy && r.Policy.ProxyId == proxyId {
			out = append(out, r)
		}
	}
	return out, nil
}

// ReassignRulesFromProxy repoints every rule targeting oldProxyId at a new
// policy, for use when a proxy is deleted.
func ReassignRulesFromProxy(oldProxyId string, newPolicy RulePolicy) error {
	c, err := Read()
	if err != nil {
		return err
	}
	changed := 0
	for i := range c.CustomizedRules {
		r := &c.CustomizedRules[i]
		if r.Policy.Kind == PolicyKindProxy && r.Policy.ProxyId == oldProxyId {
			r.Policy = newPolicy
			r.Slug = uniqueSlug(makeSlug(*r, c), slugsInUse(c, r.Id))
			changed++
		}
	}
	if changed == 0 {
		return nil
	}
	markBroken(&c)
	syncLegacyRules(&c)
	return Write(c)
}

// ── Legacy synchronisation ──────────────────────────────────────────────────

// syncLegacyRules regenerates Config.Rules from the store.
//
// This exists only so a downgrade to a build that predates the store still finds
// a usable list. Disabled rules are written with a "#" prefix purely for that
// compatibility window. Nothing in this codebase reads the field after
// migration.
func syncLegacyRules(c *Config) {
	out := make([]string, 0, len(c.CustomizedRules)+1)
	if c.SelectedRuleset != "" {
		out = append(out, c.SelectedRuleset)
	}

	groups := make([]RuleGroup, len(c.RuleGroups))
	copy(groups, c.RuleGroups)
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Order < groups[j].Order })

	appendGroup := func(gid string) {
		var rs []RuleItem
		for _, r := range c.CustomizedRules {
			if r.GroupId == gid {
				rs = append(rs, r)
			}
		}
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].Order < rs[j].Order })
		for _, r := range rs {
			raw := r.RawValue()
			if raw == "" {
				continue
			}
			if !r.Enabled {
				raw = "#" + raw
			}
			out = append(out, raw)
		}
	}
	for _, g := range groups {
		appendGroup(g.Id)
	}
	appendGroup(DefaultGroupId)

	c.Rules = out
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func indexOfRule(c Config, id string) int {
	for i, r := range c.CustomizedRules {
		if r.Id == id {
			return i
		}
	}
	return -1
}

func indexOfGroup(c Config, id string) int {
	for i, g := range c.RuleGroups {
		if g.Id == id {
			return i
		}
	}
	return -1
}

func sortGroupsByOrder(groups []RuleGroup) {
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Order < groups[j].Order })
}

func sortRulesByOrder(rules []RuleItem) {
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Order < rules[j].Order })
}

func maxOrderInGroup(c Config, groupId string) int {
	max := -1
	for _, r := range c.CustomizedRules {
		if r.GroupId != groupId {
			continue
		}
		if r.Order > max {
			max = r.Order
		}
	}
	return max
}
