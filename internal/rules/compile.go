package rules

import (
	"fmt"
	"net"
	"net/netip"
	"net/textproto"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/AUPLA-Labs/loupe/internal/ratelimit"
	"github.com/AUPLA-Labs/loupe/internal/tier"
)

const (
	maxRegexLen = 1024

	opPresent  = "present"
	opAbsent   = "absent"
	opEquals   = "equals"
	opContains = "contains"
	opRegex    = "regex"

	// maxLimitKeys caps the clients one rate limit tracks; past it new ones
	// share a bucket (see ratelimit.SetMaxKeys).
	maxLimitKeys = 100_000
)

var (
	ruleIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	listIDRE = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

	// Spelled out because Tier.String() prints singleclick, not single_click.
	ruleTiers = map[string]tier.Tier{
		"lumen_auto":   tier.LumenAuto,
		"single_click": tier.SingleClick,
		"prism":        tier.Prism,
	}
)

// Set is a validated, compiled rule file: everything the request path needs
// is parsed up front, so evaluating a rule never compiles or parses anything.
type Set struct {
	rules []*compiled // pointers: the hot loop must not copy a Rule per iteration
}

// Len is the number of rules in the set, enabled or not.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}

// compiled is one rule in evaluation form. The original is kept for
// reporting what matched.
type compiled struct {
	rule    Rule
	enabled bool
	mode    Mode
	action  Action
	tier    tier.Tier
	expires time.Time  // zero = never
	limit   *climit    // rate_limit only
	api     *APIPolicy // api only, with defaults filled in
	match   cmatch
	any     [][]ccond // OR of ANDed conditions; nil = not tested
	except  *cmatch
}

// climit is a compiled Limit with its counters.
type climit struct {
	requests int
	period   time.Duration
	by       byte   // byIP, byHeader, byCookie or byQuery
	name     string // header (canonical), cookie or query parameter name
	then     Action
	l        *ratelimit.Limiter
}

const (
	byIP byte = iota
	byHeader
	byCookie
	byQuery
)

// sameCounting reports whether two limits count the same way, so the newer
// can keep the older one's counters.
func (a *climit) sameCounting(b *climit) bool {
	return a.requests == b.requests && a.period == b.period && a.by == b.by && a.name == b.name
}

// inherit carries over the counters of every rate limit that counts the same
// way in s as in prev, so saving the rules doesn't hand every client a fresh
// budget. A limit that changed starts empty.
func (s *Set) inherit(prev *Set) {
	if s == nil || prev == nil {
		return
	}
	old := make(map[string]*climit)
	for _, c := range prev.rules {
		if c.limit != nil {
			old[c.rule.ID] = c.limit
		}
	}
	for _, c := range s.rules {
		if o := old[c.rule.ID]; o != nil && c.limit != nil && c.limit.sameCounting(o) {
			c.limit.l = o.l
		}
	}
}

// ccond is one compiled Condition.
type ccond struct {
	m   cmatch
	not bool
}

// cmatch is a Match with every value pre-parsed. A nil or empty field is not
// tested.
type cmatch struct {
	ips        []*net.IPNet
	prefixes   []netip.Prefix // ips again, for fast matching
	asns       map[uint]struct{}
	hostExact  map[string]struct{}
	hostSuffix []string // ".example.com": subdomains only, not the apex
	methods    map[string]struct{}
	paths      []textMatcher
	userAgents []textMatcher
	headers    []kvTest
	query      []kvTest
	countries  map[string]struct{}
	regCountry map[string]struct{}
	netTypes   map[string]struct{}
	netRoles   map[string]struct{}
	classes    map[string]struct{}
	lists      map[string]struct{}
	datacenter *bool
	badIP      int
	bots       map[string]struct{}
	cleared    *bool
	anomalies  map[string]struct{}
}

type textKind uint8

const (
	kindPrefix   textKind = iota
	kindExact             // also a glob with no wildcard
	kindRegex             // a regex: rule, or a glob containing ?
	kindSuffix            // glob *lit
	kindContains          // glob *lit*
	kindSegments          // glob with several *, no ?: lit*lit*lit
)

// textMatcher tests one string. Globs without ? are classified at compile time
// into plain string operations, because the regexp engine is far too slow for
// 500 rules on every request.
type textMatcher struct {
	kind  textKind
	value string   // the literal for prefix, exact, suffix and contains
	parts []string // kindSegments: the literals between stars, at least 3
	re    *regexp.Regexp
	pre   *prefilter // kindRegex: rules out most strings without running re
}

func (m textMatcher) match(s string) bool {
	switch m.kind {
	case kindPrefix:
		return strings.HasPrefix(s, m.value)
	case kindExact:
		return s == m.value
	case kindSuffix:
		return strings.HasSuffix(s, m.value)
	case kindContains:
		return strings.Contains(s, m.value)
	case kindSegments:
		return matchSegments(s, m.parts)
	}
	if m.pre != nil && !m.pre.allows(s) {
		return false
	}
	return m.re.MatchString(s)
}

// matchSegments matches lit*lit*...*lit: the first part is a prefix, the last
// a suffix and the middle ones occur in order between them without overlap.
func matchSegments(s string, parts []string) bool {
	first, last := parts[0], parts[len(parts)-1]
	if len(s) < len(first)+len(last) || !strings.HasPrefix(s, first) || !strings.HasSuffix(s, last) {
		return false
	}
	rest := s[len(first) : len(s)-len(last)]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(rest, mid)
		if i < 0 {
			return false
		}
		rest = rest[i+len(mid):]
	}
	return true
}

// compileGlob picks the cheapest matcher with the same meaning as the
// anchored expression globRegex builds: * is any run of characters, ?
// is one character, and the whole input must match.
func compileGlob(glob string) (textMatcher, string) {
	if !strings.Contains(glob, "?") {
		parts := strings.Split(glob, "*")
		switch {
		case len(parts) == 1:
			return textMatcher{kind: kindExact, value: glob}, ""
		case len(parts) == 2 && parts[1] == "":
			return textMatcher{kind: kindPrefix, value: parts[0]}, ""
		case len(parts) == 2 && parts[0] == "":
			return textMatcher{kind: kindSuffix, value: parts[1]}, ""
		case len(parts) == 3 && parts[0] == "" && parts[2] == "":
			return textMatcher{kind: kindContains, value: parts[1]}, ""
		default:
			return textMatcher{kind: kindSegments, parts: parts}, ""
		}
	}
	re, msg := compileRegex(globRegex(glob))
	return textMatcher{kind: kindRegex, re: re, pre: newPrefilter(re)}, msg
}

// kvTest is a header or query test. name is canonical for headers and as
// written for query parameters.
type kvTest struct {
	name  string
	op    string
	value string
	re    *regexp.Regexp
	pre   *prefilter
}

// Compile validates the rules and builds the set. It is all-or-nothing: if
// any rule has a problem it returns every problem found (each a *RuleError)
// and a nil set, so a half-applied file never runs.
func Compile(rs []Rule) (*Set, []error) {
	var errs []error
	seen := make(map[string]bool, len(rs))
	out := make([]*compiled, 0, len(rs))
	for i, r := range rs {
		c := compiled{rule: r, enabled: r.IsEnabled(), mode: r.Mode, action: r.Action}
		fail := func(field, format string, args ...any) {
			errs = append(errs, &RuleError{Index: i, ID: r.ID, Field: field, Msg: fmt.Sprintf(format, args...)})
		}

		switch {
		case r.ID == "":
			fail("id", "id is required")
		case !ruleIDRE.MatchString(r.ID):
			fail("id", "invalid id %q: use 1-64 lowercase letters, digits, - or _, starting with a letter or digit", r.ID)
		case seen[r.ID]:
			fail("id", "duplicate id %q", r.ID)
		}
		seen[r.ID] = true

		switch r.Mode {
		case "":
			c.mode = ModeLog
		case ModeLog, ModeEnforce:
		default:
			fail("mode", "unknown mode %q: use log or enforce", r.Mode)
		}

		switch r.Action {
		case ActionAllow, ActionBlock, ActionChallenge, ActionLog, ActionRateLimit, ActionAPI:
		case "":
			fail("action", "action is required")
		default:
			fail("action", "unknown action %q: use allow, block, challenge, rate_limit, api or log", r.Action)
		}
		if r.Action == ActionChallenge || (r.Action == ActionRateLimit && r.Limit != nil && r.Limit.Then == ActionChallenge) {
			if r.Tier == "" {
				fail("tier", "tier is required for challenge: use lumen_auto, single_click or prism")
			} else if t, ok := ruleTiers[r.Tier]; ok {
				c.tier = t
			} else {
				fail("tier", "unknown tier %q: use lumen_auto, single_click or prism", r.Tier)
			}
		} else if r.Tier != "" {
			fail("tier", "tier only applies to challenge")
		}
		if r.Action == ActionRateLimit {
			c.limit = compileLimit(r.Limit, fail)
		} else if r.Limit != nil {
			fail("limit", "limit only applies to rate_limit")
		}
		if r.Action == ActionAPI {
			c.api = compileAPI(r.API, fail)
		} else if r.API != nil {
			fail("api", "api only applies to action api")
		}

		if r.Expires != nil {
			c.expires = *r.Expires
		}

		if r.Match.empty() && len(r.Any) == 0 {
			fail("match", "match is empty: add a condition (a path prefix of / matches everything)")
		}
		c.match = compileMatch(r.Match, "match", fail)
		for gi, g := range r.Any {
			gp := fmt.Sprintf("any[%d].all", gi)
			if len(g.All) == 0 {
				fail(gp, "group is empty: add a condition or remove the group")
			}
			conds := make([]ccond, 0, len(g.All))
			for ci, cd := range g.All {
				cp := fmt.Sprintf("%s[%d]", gp, ci)
				if cd.Match.empty() {
					fail(cp, "condition is empty: give it a field")
				}
				conds = append(conds, ccond{m: compileMatch(cd.Match, cp, fail), not: cd.Not})
			}
			c.any = append(c.any, conds)
		}
		if r.Except != nil {
			if r.Except.empty() {
				fail("except", "except is empty: add a condition or remove it")
			}
			ex := compileMatch(*r.Except, "except", fail)
			c.except = &ex
		}
		out = append(out, &c)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return &Set{rules: out}, nil
}

func (m Match) empty() bool {
	return len(m.IPs) == 0 && len(m.ASNs) == 0 && len(m.Hosts) == 0 && len(m.Methods) == 0 &&
		len(m.Paths) == 0 && len(m.Headers) == 0 && len(m.Query) == 0 && len(m.UserAgents) == 0 &&
		len(m.Countries) == 0 && len(m.RegisteredCountries) == 0 && len(m.NetworkTypes) == 0 && len(m.NetworkRoles) == 0 &&
		len(m.Classes) == 0 && len(m.Lists) == 0 && m.Datacenter == nil && m.BadIPAtLeast == 0 &&
		len(m.Bots) == 0 && m.Cleared == nil && len(m.Anomalies) == 0
}

// compileLimit checks a rate_limit rule's budget and gives it fresh counters.
func compileLimit(l *Limit, fail func(field, format string, args ...any)) *climit {
	if l == nil {
		fail("limit", "limit is required for rate_limit: requests and period, optionally by and then")
		return nil
	}
	c := &climit{requests: l.Requests, then: l.Then}
	ok := true
	bad := func(field, format string, args ...any) { ok = false; fail(field, format, args...) }
	if l.Requests < 1 || l.Requests > 1_000_000 {
		bad("limit.requests", "requests must be 1 to 1000000")
	}
	if d, err := time.ParseDuration(l.Period); err != nil {
		bad("limit.period", "invalid period %q: write it like 10s, 1m or 1h", l.Period)
	} else if d < time.Second || d > 24*time.Hour {
		bad("limit.period", "period must be between 1s and 24h")
	} else {
		c.period = d
	}
	kind, name, _ := strings.Cut(l.By, ":")
	switch {
	case l.By == "" || l.By == "ip":
		c.by = byIP
	case name == "" || len(name) > 128:
		bad("limit.by", "%q needs a name of 1 to 128 characters after the colon", l.By)
	case kind == "header":
		c.by, c.name = byHeader, textproto.CanonicalMIMEHeaderKey(name)
	case kind == "cookie":
		c.by, c.name = byCookie, name
	case kind == "query":
		c.by, c.name = byQuery, name
	default:
		bad("limit.by", "unknown by %q: use ip, header:<name>, cookie:<name> or query:<name>", l.By)
	}
	switch l.Then {
	case "":
		c.then = ActionBlock
	case ActionBlock, ActionChallenge:
	default:
		bad("limit.then", "unknown then %q: use block or challenge", l.Then)
	}
	if ok {
		c.l = ratelimit.NewWithIdle(float64(c.requests)/c.period.Seconds(), float64(c.requests), c.period)
		c.l.SetMaxKeys(maxLimitKeys)
	}
	return c
}

// compileAPI validates an api rule's policy and fills in its defaults.
func compileAPI(p *APIPolicy, fail func(field, format string, args ...any)) *APIPolicy {
	if p == nil {
		fail("api", "api is required for action api: set at least auth")
		return nil
	}
	out := *p
	switch out.Auth {
	case APIAuthBackendHeader, APIAuthLoupeKeys:
		if out.Header == "" {
			out.Header = "Authorization"
			if out.Auth == APIAuthLoupeKeys {
				out.Header = "X-API-Key"
			}
		}
		if !validToken(out.Header) {
			fail("api.header", "invalid header name %q", out.Header)
		}
		out.Header = textproto.CanonicalMIMEHeaderKey(out.Header)
	case APIAuthNone:
		if out.Header != "" {
			fail("api.header", "header only applies to auth: backend_header or loupe_keys")
		}
	case "":
		fail("api.auth", "auth is required: use backend_header, loupe_keys or none")
	default:
		fail("api.auth", "unknown auth %q: use backend_header, loupe_keys or none", out.Auth)
	}
	switch out.Error {
	case "":
		out.Error = "text"
	case "text", "json":
	default:
		fail("api.error", "unknown error %q: use text or json", out.Error)
	}
	if len(out.Message) > 1024 {
		fail("api.message", "message is longer than 1024 characters")
	}
	if strings.ContainsAny(out.Realm, "\"\\\r\n") || len(out.Realm) > 128 {
		fail("api.realm", "realm must be at most 128 characters, without quotes, backslashes or line breaks")
	}
	return &out
}

// compileMatch parses m, reporting each problem through fail under the
// YAML path prefix (match, except or any[i].all[j]).
func compileMatch(m Match, prefix string, fail func(field, format string, args ...any)) cmatch {
	c := cmatch{datacenter: m.Datacenter, cleared: m.Cleared, badIP: m.BadIPAtLeast}

	for i, s := range m.IPs {
		n, hint := parseIPOrCIDR(strings.TrimSpace(s))
		if n == nil {
			fail(fmt.Sprintf("%s.ips[%d]", prefix, i), "invalid address or CIDR %q", s)
			continue
		}
		if hint != "" {
			fail(fmt.Sprintf("%s.ips[%d]", prefix, i), "%q has host bits set; did you mean %s?", s, hint)
			continue
		}
		c.ips = append(c.ips, n)
		if p, ok := prefixOf(n); ok {
			c.prefixes = append(c.prefixes, p)
		}
	}

	if len(m.ASNs) > 0 {
		c.asns = make(map[uint]struct{}, len(m.ASNs))
		for i, a := range m.ASNs {
			if a == 0 {
				// The lookup reports 0 for an unlisted address and when no
				// database is loaded, so a rule on it would match unknown
				// networks.
				fail(fmt.Sprintf("%s.asns[%d]", prefix, i), "ASN 0 is not a network")
				continue
			}
			c.asns[a] = struct{}{}
		}
	}

	for i, h := range m.Hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		rest, wild := strings.CutPrefix(h, "*.")
		field := fmt.Sprintf("%s.hosts[%d]", prefix, i)
		bracketed := strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") // IPv6 literal
		if strings.Contains(rest, ":") && !bracketed {
			fail(field, "invalid host %q (no port: hosts match without one)", m.Hosts[i])
			continue
		}
		// The request side drops one trailing dot, so a name written with
		// one would never match.
		rest = strings.TrimSuffix(rest, ".")
		h = strings.TrimSuffix(h, ".")
		if h == "" || (wild && (rest == "" || bracketed)) || strings.Contains(rest, "*") || (!wild && strings.Contains(h, "*")) {
			fail(field, "invalid host %q: use a name or *.name", m.Hosts[i])
			continue
		}
		if wild {
			c.hostSuffix = append(c.hostSuffix, "."+rest)
			continue
		}
		if c.hostExact == nil {
			c.hostExact = map[string]struct{}{}
		}
		c.hostExact[h] = struct{}{}
	}

	if len(m.Methods) > 0 {
		c.methods = make(map[string]struct{}, len(m.Methods))
		for i, s := range m.Methods {
			s = strings.ToUpper(strings.TrimSpace(s))
			if s == "" {
				fail(fmt.Sprintf("%s.methods[%d]", prefix, i), "empty method")
				continue
			}
			c.methods[s] = struct{}{}
		}
	}

	c.paths = compileTexts(m.Paths, prefix+".paths", true, fail)
	c.userAgents = compileTexts(m.UserAgents, prefix+".user_agents", false, fail)
	for i, a := range m.Anomalies {
		if !slices.Contains(PathAnomalies, a) {
			fail(fmt.Sprintf("%s.anomalies[%d]", prefix, i), "unknown anomaly %q: use %s", a, strings.Join(PathAnomalies, ", "))
			continue
		}
		if c.anomalies == nil {
			c.anomalies = make(map[string]struct{})
		}
		c.anomalies[a] = struct{}{}
	}
	c.headers = compileKV(m.Headers, prefix+".headers", true, fail)
	c.query = compileKV(m.Query, prefix+".query", false, fail)

	for i, s := range m.Countries {
		if !isAlpha2(s) {
			fail(fmt.Sprintf("%s.countries[%d]", prefix, i), "invalid country %q: use a two-letter ISO 3166 code", s)
			continue
		}
		if c.countries == nil {
			c.countries = map[string]struct{}{}
		}
		c.countries[strings.ToUpper(s)] = struct{}{}
	}

	for i, s := range m.RegisteredCountries {
		if !isAlpha2(s) {
			fail(fmt.Sprintf("%s.registered_countries[%d]", prefix, i), "invalid country %q: use a two-letter ISO 3166 code", s)
			continue
		}
		c.regCountry = addTo(c.regCountry, strings.ToUpper(s))
	}
	oneOf := func(field string, vals, known []string) map[string]struct{} {
		var out map[string]struct{}
		for i, v := range vals {
			if !slices.Contains(known, v) {
				fail(fmt.Sprintf("%s.%s[%d]", prefix, field, i), "unknown value %q: one of %s", v, strings.Join(known, ", "))
				continue
			}
			out = addTo(out, v)
		}
		return out
	}
	c.netTypes = oneOf("network_types", m.NetworkTypes, NetworkTypes)
	c.netRoles = oneOf("network_roles", m.NetworkRoles, NetworkRoles)
	c.classes = oneOf("classes", m.Classes, AddressClasses)
	for i, l := range m.Lists {
		if !listIDRE.MatchString(l) {
			fail(fmt.Sprintf("%s.lists[%d]", prefix, i), "invalid list id %q: lower-case letters, digits and _", l)
			continue
		}
		c.lists = addTo(c.lists, l)
	}

	if m.BadIPAtLeast < 0 {
		fail(prefix+".bad_ip_at_least", "must be 0 or more")
	}

	if len(m.Bots) > 0 {
		c.bots = make(map[string]struct{}, len(m.Bots))
		for i, b := range m.Bots {
			if b == "" {
				// Bot() reports "" for "no verified bot", so an empty ID
				// would match every request that is not from one.
				fail(fmt.Sprintf("%s.bots[%d]", prefix, i), "empty bot id")
				continue
			}
			c.bots[b] = struct{}{}
		}
	}
	return c
}

// parseIPOrCIDR returns the network for a CIDR, or a /32 or /128 for a bare
// address. It returns nil when s is neither. When a CIDR has host bits set,
// which would silently widen it (203.0.113.77/16 is the whole /16), it also
// returns the corrected spelling to suggest. The network is still returned,
// but the caller must reject it.
func parseIPOrCIDR(s string) (*net.IPNet, string) {
	if ip, n, err := net.ParseCIDR(s); err == nil {
		if ip.Equal(n.IP) {
			return n, ""
		}
		// An address ending in a non-zero byte reads as a host, so the
		// likelier intent is that one address; otherwise the masked network.
		ones, bits := n.Mask.Size()
		host := ip
		if v4 := ip.To4(); v4 != nil {
			host = v4
		}
		if host[len(host)-1] != 0 {
			return n, fmt.Sprintf("%s/%d", host, bits)
		}
		return n, fmt.Sprintf("%s/%d", n.IP, ones)
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, ""
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, ""
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, ""
}

// prefixOf converts a network to a netip.Prefix, which matches much faster
// than IPNet.Contains. An IPv4-mapped IPv6 network becomes the IPv4 one, as
// the addresses are unmapped before matching.
func prefixOf(n *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false
	}
	if addr.Is4In6() && ones >= 96 {
		addr, ones = addr.Unmap(), ones-96
	}
	p := netip.PrefixFrom(addr, ones)
	return p, p.IsValid()
}

func isAlpha2(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i < 2; i++ {
		c := s[i] | 0x20
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// compileRegex compiles an RE2 pattern, refusing very long ones. The error
// text is ready to use as a RuleError message.
func compileRegex(expr string) (*regexp.Regexp, string) {
	if utf8.RuneCountInString(expr) > maxRegexLen {
		return nil, fmt.Sprintf("regex too long: at most %d characters", maxRegexLen)
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, "invalid regex: " + err.Error()
	}
	return re, ""
}

// globRegex turns Loupe's wildcard into an anchored expression: * is any run
// of characters (including /), ? is one character, the rest is literal.
func globRegex(glob string) string {
	var b strings.Builder
	b.WriteString("(?s)^")
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return b.String()
}

// compileTexts compiles path or User-Agent tests. With fold they ignore case
// and expect the input lower-cased (as paths are matched).
func compileTexts(ps []PathMatch, field string, fold bool, fail func(field, format string, args ...any)) []textMatcher {
	var out []textMatcher
	low := func(s string) string { return s }
	if fold {
		low = strings.ToLower
	}
	for i, p := range ps {
		f := fmt.Sprintf("%s[%d]", field, i)
		set := 0
		for _, s := range []string{p.Prefix, p.Exact, p.Glob, p.Regex} {
			if s != "" {
				set++
			}
		}
		if set != 1 {
			fail(f, "set exactly one of prefix, exact, glob, regex")
			continue
		}
		switch {
		case p.Prefix != "":
			out = append(out, textMatcher{kind: kindPrefix, value: low(p.Prefix)})
		case p.Exact != "":
			out = append(out, textMatcher{kind: kindExact, value: low(p.Exact)})
		case p.Glob != "":
			if utf8.RuneCountInString(p.Glob) > maxRegexLen {
				fail(f+".glob", "glob too long: at most %d characters", maxRegexLen)
				continue
			}
			tm, msg := compileGlob(low(p.Glob))
			if msg != "" {
				fail(f+".glob", "%s", strings.Replace(msg, "regex", "glob", 1))
				continue
			}
			out = append(out, tm)
		default:
			re, msg := compileRegex(p.Regex)
			if msg != "" {
				fail(f+".regex", "%s", msg)
				continue
			}
			if fold {
				re = regexp.MustCompile("(?i)" + p.Regex) // valid: the pattern alone compiled
			}
			out = append(out, textMatcher{kind: kindRegex, re: re, pre: newPrefilter(re)})
		}
	}
	return out
}

func compileKV(hs []HeaderMatch, field string, canonical bool, fail func(field, format string, args ...any)) []kvTest {
	var out []kvTest
	for i, h := range hs {
		f := fmt.Sprintf("%s[%d]", field, i)
		ok := true
		if h.Name == "" {
			fail(f+".name", "name is required")
			ok = false
		}
		t := kvTest{name: h.Name, op: h.Op, value: h.Value}
		if canonical {
			t.name = textproto.CanonicalMIMEHeaderKey(h.Name)
		}
		switch h.Op {
		case opPresent, opAbsent:
			if h.Value != "" {
				fail(f+".value", "value not allowed with %s", h.Op)
				ok = false
			}
		case opEquals, opContains:
			if h.Value == "" {
				fail(f+".value", "value is required with %s", h.Op)
				ok = false
			}
		case opRegex:
			if h.Value == "" {
				fail(f+".value", "value is required with %s", h.Op)
				ok = false
			} else if re, msg := compileRegex(h.Value); msg != "" {
				fail(f+".value", "%s", msg)
				ok = false
			} else {
				t.re = re
				t.pre = newPrefilter(re)
			}
		default:
			fail(f+".op", "unknown op %q: use present, absent, equals, contains or regex", h.Op)
			ok = false
		}
		if ok {
			out = append(out, t)
		}
	}
	return out
}

// validToken reports whether s is an HTTP token (RFC 9110 §5.6.2), the
// syntax of a header name.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

func addTo(m map[string]struct{}, v string) map[string]struct{} {
	if m == nil {
		m = map[string]struct{}{}
	}
	m[v] = struct{}{}
	return m
}
