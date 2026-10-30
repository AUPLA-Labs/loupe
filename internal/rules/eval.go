package rules

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

// Facts is everything the evaluator may ask about one request. Cheap facts
// are plain fields. Expensive ones (an ASN lookup, a bot DNS check) are
// functions that Evaluate calls at most once, and only when a rule that got
// that far needs them. A nil function means the fact is unknown, and a rule
// that needs an unknown fact does not match.
type Facts struct {
	Req       *http.Request
	IP        net.IP
	ClientKey string    // the client as rate limits count it (Loupe's IP key); "" counts by IP
	Now       time.Time // zero means time.Now()
	DryRun    bool      // spend nothing: rate limits are reported as counting, never as exceeded
	Path      string    // the canonical path rules match; "" = Req.URL.Path
	Anomalies []string  // what canonicalising the path undid (see PathAnomalies)

	ASN        func() (uint, bool)
	Datacenter func() (isDatacenter, known bool) // known is false when the network is unknown
	Country    func() string                     // upper-case ISO 3166 alpha-2 code of where the address is used, "" if unknown
	Network    func() Network                    // the network's type and registration, and the address's classes
	BadIP      func() int
	Bot        func() string // verified bot ID, "" when none
	Cleared    func() bool
}

// Network is what the network database and the published address lists
// say about the client. Empty fields are unknown.
type Network struct {
	RegisteredCountry string   // upper-case ISO 3166 alpha-2
	Type              string   // one of NetworkTypes
	Role              string   // one of NetworkRoles
	Classes           []string // of AddressClasses
	List              string   // ID of the published list the address is in
}

// CountryFunc looks up the country of an address as an upper-case ISO 3166
// alpha-2 code, or "". Rules store codes upper-cased and compare them as
// returned, so a source must not return lower case.
type CountryFunc func(net.IP) string

// Hit is the rule that decided a request.
type Hit struct {
	ID     string
	Action Action
	Tier   tier.Tier // challenge, or a rate limit whose Then is challenge

	Then       Action        // rate_limit only: what to do now that it is exceeded
	RetryAfter time.Duration // rate_limit only: until the client has a request again

	// API is the policy of the first enforced api rule the request matched,
	// set on whatever hit ends the search. An api rule doesn't end it, so
	// blocks, allows and rate limits below it still apply; when none does,
	// the hit is the api rule itself. Challenge rules below it are skipped:
	// an API client can't take a challenge.
	API   *APIPolicy
	APIID string
}

// evalState holds what one Evaluate call has learned so far. It lives on the
// stack: lazy facts are memoised here so that no matter how many rules ask,
// each is fetched once, and nothing is allocated per rule.
type evalState struct {
	f *Facts

	now     time.Time
	haveNow bool

	lowPath  string
	havePath bool

	hostBuf  [255]byte
	hostLen  int
	hostLong []byte // only for a Host longer than hostBuf, which is not a real name
	haveHost bool

	addr     netip.Addr
	addrOK   bool
	haveAddr bool

	ua     string
	haveUA bool

	query     url.Values
	haveQuery bool

	country     string
	haveCountry bool

	network     Network
	haveNetwork bool

	asn     uint
	asnOK   bool
	haveASN bool

	datacenter     bool
	datacenterOK   bool
	haveDatacenter bool

	badIP     int
	haveBadIP bool

	bot     string
	haveBot bool

	cleared     bool
	haveCleared bool
}

// Evaluate runs the rules in file order against one request. Matches of
// log-only rules (mode log, or action log) are collected in logged and
// evaluation continues; the first other match is returned as the hit. A nil
// set evaluates to nothing.
//
// Cost for operators: a plain prefix, exact, glob, IP, host or method test
// costs well under 0.1 µs per rule. A regex test costs about 0.6 µs per
// request when the pattern contains a literal word that rules most values out
// (the common case), and about 1.8 µs when it has none, on a typical
// User-Agent. Prefer prefix, exact and glob matches over regex.
func (s *Set) Evaluate(f *Facts) (hit *Hit, logged []string) {
	return s.evaluate(f, nil)
}

// DryRun is Evaluate for a request that was never sent: it spends nothing
// from any rate limit and lists the limits the request would count toward.
func (s *Set) DryRun(f *Facts) (hit *Hit, logged, counted []string) {
	dry := *f
	dry.DryRun = true
	counted = []string{}
	hit, logged = s.evaluate(&dry, &counted)
	return hit, logged, counted
}

func (s *Set) evaluate(f *Facts, counted *[]string) (hit *Hit, logged []string) {
	if s == nil {
		return nil, nil
	}
	st := evalState{f: f}
	var api *compiled
	defer func() {
		if api == nil {
			return
		}
		if hit == nil {
			hit = &Hit{ID: api.rule.ID, Action: ActionAPI}
		}
		hit.API, hit.APIID = api.api, api.rule.ID
	}()
	for _, c := range s.rules {
		if !c.enabled {
			continue
		}
		if !c.expires.IsZero() && !c.expires.After(st.nowTime()) {
			continue
		}
		if !c.match.matches(&st) {
			continue
		}
		if c.any != nil && !anyGroup(c.any, &st) {
			continue
		}
		if c.except != nil && c.except.matches(&st) {
			continue
		}
		if c.limit != nil {
			// Within the budget a rate limit is no decision: the search goes
			// on. Over it, an enforced limit decides; a logged one is noted.
			if f.DryRun {
				if counted != nil {
					*counted = append(*counted, c.rule.ID)
				}
				continue
			}
			ok, wait := c.limit.l.Take(c.limit.key(&st))
			if ok {
				continue
			}
			if c.mode == ModeLog {
				logged = append(logged, c.rule.ID)
				continue
			}
			return &Hit{ID: c.rule.ID, Action: ActionRateLimit, Tier: c.tier, Then: c.limit.then, RetryAfter: wait}, logged
		}
		if c.mode == ModeLog || c.action == ActionLog {
			logged = append(logged, c.rule.ID)
			continue
		}
		switch {
		case c.action == ActionAPI:
			if api == nil {
				api = c
			}
			continue
		case c.action == ActionChallenge && api != nil:
			continue
		}
		return &Hit{ID: c.rule.ID, Action: c.action, Tier: c.tier}, logged
	}
	return nil, logged
}

// key is who a request counts as for the limit: the header, cookie or query
// value it is keyed by, or the client when that is missing, so leaving the
// value out doesn't escape the limit. Values are hashed to bound memory.
func (c *climit) key(st *evalState) string {
	var v string
	switch c.by {
	case byHeader:
		v = st.f.Req.Header.Get(c.name)
	case byCookie:
		if ck, err := st.f.Req.Cookie(c.name); err == nil {
			v = ck.Value
		}
	case byQuery:
		v = st.queryValues().Get(c.name)
	}
	if v != "" {
		h := uint64(14695981039346656037) // FNV-1a
		for i := 0; i < len(v); i++ {
			h ^= uint64(v[i])
			h *= 1099511628211
		}
		return "v" + strconv.FormatUint(h, 36)
	}
	if st.f.ClientKey != "" {
		return "c" + st.f.ClientKey
	}
	return "c" + st.f.IP.String()
}

func (st *evalState) nowTime() time.Time {
	if !st.haveNow {
		st.now = st.f.Now
		if st.now.IsZero() {
			st.now = time.Now()
		}
		st.haveNow = true
	}
	return st.now
}

// matches reports whether every field that is set matches. Fields run from
// cheapest to dearest, so a rule that fails on its path never reaches a
// lookup.
func (c *cmatch) matches(st *evalState) bool {
	r := st.f.Req

	if len(c.methods) > 0 {
		if _, ok := c.methods[r.Method]; !ok {
			return false
		}
	}
	if len(c.ips) > 0 && !c.matchIP(st) {
		return false
	}
	if len(c.hostExact) > 0 || len(c.hostSuffix) > 0 {
		if !c.matchHost(st.hostname()) {
			return false
		}
	}
	if len(c.paths) > 0 && !anyText(c.paths, st.path()) {
		return false
	}
	if c.anomalies != nil && !c.matchAnomaly(st.f.Anomalies) {
		return false
	}
	if len(c.userAgents) > 0 && !anyText(c.userAgents, st.userAgent()) {
		return false
	}
	if len(c.headers) > 0 && !anyHeader(c.headers, r) {
		return false
	}
	if len(c.query) > 0 && !anyKV(c.query, st.queryValues()) {
		return false
	}

	// Lazy facts, each fetched at most once per request, cheapest first.
	// Bot() can mean a DNS check, so it goes last.
	if c.cleared != nil {
		if st.f.Cleared == nil || st.clearedValue() != *c.cleared {
			return false
		}
	}
	if c.badIP > 0 {
		if st.f.BadIP == nil || st.badIPValue() < c.badIP {
			return false
		}
	}
	if len(c.countries) > 0 {
		if st.f.Country == nil {
			return false
		}
		if _, ok := c.countries[st.countryValue()]; !ok {
			return false
		}
	}
	if c.regCountry != nil || c.netTypes != nil || c.netRoles != nil || c.classes != nil || c.lists != nil {
		if st.f.Network == nil {
			return false
		}
		n := st.networkValue()
		if !inSet(c.regCountry, n.RegisteredCountry) || !inSet(c.netTypes, n.Type) || !inSet(c.netRoles, n.Role) || !inSet(c.lists, n.List) {
			return false
		}
		if c.classes != nil && !slices.ContainsFunc(n.Classes, func(x string) bool { _, ok := c.classes[x]; return ok }) {
			return false
		}
	}
	if c.asns != nil {
		asn, ok := st.asnValue()
		if !ok {
			return false
		}
		if _, listed := c.asns[asn]; !listed {
			return false
		}
	}
	if c.datacenter != nil {
		if st.f.Datacenter == nil {
			return false
		}
		dc, known := st.datacenterValue()
		if !known || dc != *c.datacenter {
			return false
		}
	}
	if len(c.bots) > 0 {
		if st.f.Bot == nil {
			return false
		}
		if _, ok := c.bots[st.botValue()]; !ok {
			return false
		}
	}
	return true
}

// path is the canonical path, lower-cased: path rules ignore case.
func (st *evalState) path() string {
	if !st.havePath {
		p := st.f.Path
		if p == "" {
			p = st.f.Req.URL.Path
		}
		st.lowPath, st.havePath = strings.ToLower(p), true
	}
	return st.lowPath
}

func (c *cmatch) matchAnomaly(as []string) bool {
	for _, a := range as {
		if _, ok := c.anomalies[a]; ok {
			return true
		}
	}
	return false
}

// anyGroup reports whether every condition of at least one group holds.
func anyGroup(groups [][]ccond, st *evalState) bool {
	for _, g := range groups {
		ok := true
		for i := range g {
			if g[i].m.matches(st) == g[i].not {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func (c *cmatch) matchIP(st *evalState) bool {
	addr, ok := st.clientAddr()
	if !ok {
		return false
	}
	for _, p := range c.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// matchHost tests an already lower-cased host name with no port. The
// conversions below are comparisons and map lookups, which do not allocate.
func (c *cmatch) matchHost(h []byte) bool {
	if _, ok := c.hostExact[string(h)]; ok {
		return true
	}
	for _, suf := range c.hostSuffix {
		if len(h) > len(suf) && string(h[len(h)-len(suf):]) == suf {
			return true
		}
	}
	return false
}

func anyText(ms []textMatcher, s string) bool {
	for i := range ms {
		if ms[i].match(s) {
			return true
		}
	}
	return false
}

// anyHeader tests the request's headers. Go moves Host out of r.Header into
// r.Host, so a test named Host reads that instead.
func anyHeader(ts []kvTest, r *http.Request) bool {
	for i := range ts {
		t := &ts[i]
		var vals []string
		if t.name == "Host" {
			var one [1]string
			if r.Host != "" {
				one[0] = r.Host
				vals = one[:]
			}
			if t.test(vals) {
				return true
			}
			continue
		}
		if t.test(r.Header[t.name]) {
			return true
		}
	}
	return false
}

func anyKV(ts []kvTest, values url.Values) bool {
	for i := range ts {
		if ts[i].test(values[ts[i].name]) {
			return true
		}
	}
	return false
}

// test applies the op to the values of one header or query parameter. Any
// value may satisfy equals, contains and regex; absent means no value at all.
func (t *kvTest) test(vals []string) bool {
	switch t.op {
	case opPresent:
		return len(vals) > 0
	case opAbsent:
		return len(vals) == 0
	case opEquals:
		for _, v := range vals {
			if v == t.value {
				return true
			}
		}
	case opContains:
		for _, v := range vals {
			if strings.Contains(v, t.value) {
				return true
			}
		}
	case opRegex:
		for _, v := range vals {
			if (t.pre == nil || t.pre.allows(v)) && t.re.MatchString(v) {
				return true
			}
		}
	}
	return false
}

// hostname returns Req.Host lower-cased with any port removed, computed once
// into a buffer on the stack so a mixed-case Host does not allocate.
func (st *evalState) hostname() []byte {
	if !st.haveHost {
		st.haveHost = true
		st.setHostname(st.f.Req.Host)
	}
	if st.hostLong != nil {
		return st.hostLong
	}
	// Slicing the array afresh, rather than keeping a slice of it in st,
	// is what lets st stay on the stack.
	return st.hostBuf[:st.hostLen]
}

func (st *evalState) setHostname(h string) {
	if strings.HasPrefix(h, "[") {
		// IPv6 literal: keep the brackets, drop what follows them.
		if i := strings.IndexByte(h, ']'); i >= 0 {
			h = h[:i+1]
		}
	} else if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.IndexByte(h, ':') == i {
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".") // a fully qualified name is the same host
	if len(h) > len(st.hostBuf) {
		st.hostLong = []byte(strings.ToLower(h))
		return
	}
	for i := 0; i < len(h); i++ {
		ch := h[i]
		if 'A' <= ch && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		st.hostBuf[i] = ch
	}
	st.hostLen = len(h)
}

// clientAddr is Facts.IP as a netip.Addr, IPv4-mapped addresses unmapped.
func (st *evalState) clientAddr() (netip.Addr, bool) {
	if !st.haveAddr {
		st.haveAddr = true
		if a, ok := netip.AddrFromSlice(st.f.IP); ok {
			st.addr, st.addrOK = a.Unmap(), true
		}
	}
	return st.addr, st.addrOK
}

// userAgent is Req.UserAgent() fetched once: Header.Get canonicalises the key
// on every call, which adds up over hundreds of user-agent rules.
func (st *evalState) userAgent() string {
	if !st.haveUA {
		st.haveUA = true
		if v := st.f.Req.Header["User-Agent"]; len(v) > 0 {
			st.ua = v[0]
		}
	}
	return st.ua
}

// queryValues parses the query string the first time a rule needs it.
func (st *evalState) queryValues() url.Values {
	if !st.haveQuery {
		st.query = st.f.Req.URL.Query()
		st.haveQuery = true
	}
	return st.query
}

func (st *evalState) countryValue() string {
	if !st.haveCountry {
		st.haveCountry = true
		st.country = st.f.Country()
	}
	return st.country
}

func (st *evalState) networkValue() Network {
	if !st.haveNetwork {
		st.haveNetwork = true
		st.network = st.f.Network()
	}
	return st.network
}

// inSet: a nil set is not tested; otherwise v must be in it.
func inSet(set map[string]struct{}, v string) bool {
	if set == nil {
		return true
	}
	_, ok := set[v]
	return ok
}

func (st *evalState) asnValue() (uint, bool) {
	if !st.haveASN {
		st.haveASN = true
		if st.f.ASN != nil {
			st.asn, st.asnOK = st.f.ASN()
		}
	}
	return st.asn, st.asnOK
}

func (st *evalState) datacenterValue() (dc, known bool) {
	if !st.haveDatacenter {
		st.haveDatacenter = true
		st.datacenter, st.datacenterOK = st.f.Datacenter()
	}
	return st.datacenter, st.datacenterOK
}

func (st *evalState) badIPValue() int {
	if !st.haveBadIP {
		st.haveBadIP = true
		st.badIP = st.f.BadIP()
	}
	return st.badIP
}

func (st *evalState) botValue() string {
	if !st.haveBot {
		st.haveBot = true
		st.bot = st.f.Bot()
	}
	return st.bot
}

func (st *evalState) clearedValue() bool {
	if !st.haveCleared {
		st.haveCleared = true
		st.cleared = st.f.Cleared()
	}
	return st.cleared
}
