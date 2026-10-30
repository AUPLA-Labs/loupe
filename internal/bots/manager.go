package bots

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Options struct {
	PolicyFile string        // YAML policy the dashboard edits
	RangesDir  string        // cache directory for fetched IP lists
	Refresh    time.Duration // how often IP lists are re-fetched; default 24h
	VerifyTTL  time.Duration // how long a verification result is cached per bot+IP; default 1h
	// ASN returns the network an IP belongs to (0 if unknown). Optional;
	// without it ASN-verified bots (Meta, X, LinkedIn) never verify.
	ASN func(net.IP) uint
	// Legacy carries the pre-catalog good_bots / ai_crawlers settings,
	// migrated into a new policy file the first time one doesn't exist.
	Legacy *Legacy
}

type Legacy struct {
	Allow []LegacyBot // good_bots.bots and ai_crawlers.allow: verified bots that were let through
	Block []string    // ai_crawlers.block: UA substrings that were refused
}

type LegacyBot struct {
	Name       string
	UAContains string
	ValidPTR   []string
}

// Decision is the result of classifying one request.
type Decision struct {
	Bot        *Bot
	Verified   bool
	Spoofed    bool   // claims a verifiable bot but failed verification
	Method     string // how it verified: "ip list", "network", "reverse dns"
	Action     Action
	Overridden bool // Action comes from a per-bot override, not the category
	// Unverifiable is set when the bot has no way to be verified and the
	// site blocks such bots (policy unverifiable: block).
	Unverifiable bool
}

// Status names the verification outcome for events and logs.
func (d Decision) Status() string {
	switch {
	case d.Bot == nil:
		return ""
	case d.Verified:
		return "verified"
	case d.Spoofed:
		return "spoofed"
	case !d.Bot.Verifiable():
		return "unverifiable"
	case d.Action == Block:
		return "claimed" // blocked on the claim alone; verification wasn't needed
	default:
		return "unverifiable"
	}
}

type state struct {
	policy  Policy
	mtime   time.Time
	bots    []*Bot
	byID    map[string]*Bot
	tokens  []token // lowered, longest first
	loadErr string  // last failed reload of the policy file; the previous policy stays in use
}

type token struct {
	s   string
	bot *Bot
}

type vEntry struct {
	ok      bool
	method  string
	expires time.Time
}

type Manager struct {
	opts    Options
	catalog *Catalog
	ranges  *rangeStore
	state   atomic.Pointer[state]
	saveMu  sync.Mutex
	written atomic.Pointer[func(data []byte)] // nil until SetOnPolicyWritten

	vmu    sync.RWMutex
	vcache map[string]vEntry

	// Overridable for tests.
	lookupAddr func(ctx context.Context, ip string) ([]string, error)
	lookupHost func(ctx context.Context, host string) ([]string, error)
}

func New(opts Options) (*Manager, error) {
	if opts.Refresh <= 0 {
		opts.Refresh = 24 * time.Hour
	}
	if opts.VerifyTTL <= 0 {
		opts.VerifyTTL = time.Hour
	}
	cat, err := loadCatalog()
	if err != nil {
		return nil, err
	}
	m := &Manager{
		opts:       opts,
		catalog:    cat,
		ranges:     newRangeStore(opts.RangesDir, opts.Refresh),
		vcache:     make(map[string]vEntry),
		lookupAddr: net.DefaultResolver.LookupAddr,
		lookupHost: net.DefaultResolver.LookupHost,
	}

	p, mtime, err := loadPolicy(opts.PolicyFile)
	switch {
	case err == nil:
		if p, err = p.validate(cat); err != nil {
			return nil, fmt.Errorf("bots policy %s: %w", opts.PolicyFile, err)
		}
	case errors.Is(err, os.ErrNotExist):
		p = m.migrate(opts.Legacy)
		if opts.PolicyFile != "" {
			if err := savePolicy(opts.PolicyFile, p); err != nil {
				log.Printf("bots: write initial policy %s: %v", opts.PolicyFile, err)
			} else {
				log.Printf("bots: created %s", opts.PolicyFile)
				if _, mt, err := loadPolicy(opts.PolicyFile); err == nil {
					mtime = mt
				}
			}
		}
	default:
		return nil, fmt.Errorf("bots policy %s: %w", opts.PolicyFile, err)
	}
	m.apply(p, mtime, "")

	for _, u := range m.urls() {
		m.ranges.loadCached(u)
	}
	return m, nil
}

// Run keeps IP lists fresh and picks up hand edits to the policy file. It
// returns when ctx is done.
func (m *Manager) Run(ctx context.Context) {
	m.ranges.refreshDue(ctx, m.urls(), false)
	refresh := time.NewTicker(10 * time.Minute)
	watch := time.NewTicker(5 * time.Second)
	sweep := time.NewTicker(15 * time.Minute)
	defer refresh.Stop()
	defer watch.Stop()
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh.C:
			m.ranges.refreshDue(ctx, m.urls(), false)
		case <-watch.C:
			m.reloadIfChanged()
		case <-sweep.C:
			m.sweepCache()
		}
	}
}

// RefreshAll re-fetches every IP list now, regardless of age.
func (m *Manager) RefreshAll(ctx context.Context) {
	m.ranges.refreshDue(ctx, m.urls(), true)
	m.clearCache()
}

func (m *Manager) apply(p Policy, mtime time.Time, loadErr string) {
	st := &state{policy: p, mtime: mtime, byID: map[string]*Bot{}, loadErr: loadErr}
	for i := range m.catalog.Bots {
		st.bots = append(st.bots, &m.catalog.Bots[i])
	}
	for i := range p.Custom {
		st.bots = append(st.bots, &p.Custom[i])
	}
	for _, b := range st.bots {
		st.byID[b.ID] = b
		for _, t := range b.UA {
			st.tokens = append(st.tokens, token{strings.ToLower(t), b})
		}
	}
	sort.SliceStable(st.tokens, func(i, j int) bool { return len(st.tokens[i].s) > len(st.tokens[j].s) })
	m.state.Store(st)
	m.clearCache()
}

func (m *Manager) reloadIfChanged() {
	if m.opts.PolicyFile == "" {
		return
	}
	cur := m.state.Load()
	fi, err := os.Stat(m.opts.PolicyFile)
	if err != nil || fi.ModTime().Equal(cur.mtime) {
		return
	}
	p, data, mtime, err := loadPolicyBytes(m.opts.PolicyFile)
	if err == nil {
		p, err = p.validate(m.catalog)
	}
	if err != nil {
		log.Printf("bots: %s not applied: %v", m.opts.PolicyFile, err)
		m.apply(cur.policy, fi.ModTime(), err.Error())
		return
	}
	log.Printf("bots: reloaded %s", m.opts.PolicyFile)
	m.apply(p, mtime, "")
	m.policyWritten(data)
	go m.ranges.refreshDue(context.Background(), m.urls(), false) // a custom bot may add a list
}

// Save validates and stores a new policy, applying it immediately.
func (m *Manager) Save(p Policy) (Policy, error) {
	m.saveMu.Lock()
	defer m.saveMu.Unlock()
	p, err := p.validate(m.catalog)
	if err != nil {
		return p, err
	}
	var data []byte
	if m.opts.PolicyFile != "" {
		var err error
		if data, err = renderPolicy(p); err != nil {
			return p, err
		}
		if err := writePolicy(m.opts.PolicyFile, data); err != nil {
			return p, err
		}
	}
	var mtime time.Time
	if fi, err := os.Stat(m.opts.PolicyFile); err == nil {
		mtime = fi.ModTime()
	}
	m.apply(p, mtime, "")
	if data != nil {
		m.policyWritten(data)
	}
	go m.ranges.refreshDue(context.Background(), m.urls(), false)
	return p, nil
}

// SetOnPolicyWritten registers fn to receive the policy file's bytes each
// time Save writes it and each time a hand edit is applied, so the dashboard
// can keep a version of it. fn runs synchronously before Save or the reload
// returns, and not for a rejected save or an unusable hand edit.
func (m *Manager) SetOnPolicyWritten(fn func(data []byte)) { m.written.Store(&fn) }

func (m *Manager) policyWritten(data []byte) {
	if fn := m.written.Load(); fn != nil {
		(*fn)(data)
	}
}

// PolicyFile is the path of the policy file ("" when it is memory-only).
func (m *Manager) PolicyFile() string { return m.opts.PolicyFile }

// Policy returns the policy in effect.
func (m *Manager) Policy() Policy { return m.state.Load().policy }

// urls lists every IP list referenced by any bot, catalog or custom.
func (m *Manager) urls() []string {
	seen := map[string]bool{}
	var out []string
	for _, b := range m.state.Load().bots {
		for _, r := range b.Ranges {
			if u := m.catalog.sourceURL(r); u != "" && !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	return out
}

func (st *state) match(ua string) *Bot {
	if ua == "" {
		return nil
	}
	lower := strings.ToLower(ua)
	for _, t := range st.tokens {
		if strings.Contains(lower, t.s) {
			return t.bot
		}
	}
	return nil
}

// actionFor returns the effective action for b and whether it's a per-bot override.
func (m *Manager) actionFor(st *state, b *Bot) (Action, bool) {
	if a, ok := st.policy.Bots[b.ID]; ok {
		return a, true
	}
	if a, ok := st.policy.Categories[b.Category]; ok {
		return a, false
	}
	if c := m.catalog.category(b.Category); c != nil {
		return c.Default, false
	}
	return Standard, false
}

// effectiveAction applies the rules a bot's configured action can't override
// on its own: an unverifiable bot can never be allowed, and unless the site
// exempts it with an explicit per-bot "standard", the unverifiable policy
// decides. The bool reports a per-bot override; the second bool whether the
// unverifiable policy decided.
func (m *Manager) effectiveAction(st *state, b *Bot) (Action, bool, bool) {
	a, over := m.actionFor(st, b)
	if b.Verifiable() || a == Block || (over && a == Standard) {
		return a, over, false
	}
	if st.policy.Unverifiable == Block {
		return Block, over, true
	}
	return Standard, over, false
}

// Classify identifies the bot a request claims to be, verifies the claim and
// returns the action to take. A zero Decision (Bot == nil) means the
// User-Agent names no known bot.
func (m *Manager) Classify(ip net.IP, ua string) Decision {
	st := m.state.Load()
	b := st.match(ua)
	if b == nil {
		return Decision{}
	}
	action, over, unver := m.effectiveAction(st, b)
	d := Decision{Bot: b, Action: action, Overridden: over, Unverifiable: unver}
	if action == Block || !b.Verifiable() || ip == nil {
		if d.Action == Allow {
			d.Action = Standard // a header alone is never enough to skip protection
		}
		return d
	}
	d.Verified, d.Method = m.verifyCached(b, ip)
	if !d.Verified {
		d.Spoofed = true
		if action == Allow {
			d.Action = Standard
		}
		if st.policy.Spoofed == Block {
			d.Action = Block
		}
	}
	return d
}

func (m *Manager) verifyCached(b *Bot, ip net.IP) (bool, string) {
	key := b.ID + "|" + ip.String()
	m.vmu.RLock()
	e, ok := m.vcache[key]
	m.vmu.RUnlock()
	if ok && time.Now().Before(e.expires) {
		return e.ok, e.method
	}
	checks := m.verify(context.Background(), b, ip, false)
	ok, method := false, ""
	for _, c := range checks {
		if c.OK {
			ok, method = true, c.Method
			break
		}
	}
	m.vmu.Lock()
	m.vcache[key] = vEntry{ok: ok, method: method, expires: time.Now().Add(m.opts.VerifyTTL)}
	m.vmu.Unlock()
	return ok, method
}

// Check is one verification method's result, for the dashboard's tester.
type Check struct {
	Method string `json:"method"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// verify runs b's verification methods, cheapest first. Unless all is set it
// stops at the first that passes.
func (m *Manager) verify(ctx context.Context, b *Bot, ip net.IP, all bool) []Check {
	var out []Check
	done := func(c Check) bool { out = append(out, c); return c.OK && !all }

	if len(b.Ranges) > 0 || len(b.CIDRs) > 0 {
		c := Check{Method: "ip list"}
		var static []*net.IPNet
		for _, s := range b.CIDRs {
			if n := parseNet(s); n != nil {
				static = append(static, n)
			}
		}
		total := len(static)
		if containsIP(static, ip) {
			c.OK, c.Detail = true, "in the bot's static ranges"
		}
		for _, r := range b.Ranges {
			if c.OK {
				break
			}
			u := m.catalog.sourceURL(r)
			nets := m.ranges.nets(u)
			total += len(nets)
			if containsIP(nets, ip) {
				c.OK, c.Detail = true, "listed in "+r
			}
		}
		if !c.OK {
			c.Detail = fmt.Sprintf("not in any of %d published ranges", total)
			if total == 0 {
				c.Detail = "no IP list loaded yet"
			}
		}
		if done(c) {
			return out
		}
	}

	if len(b.ASN) > 0 {
		c := Check{Method: "network"}
		var asn uint
		if m.opts.ASN != nil {
			asn = m.opts.ASN(ip)
		}
		for _, a := range b.ASN {
			if a == asn {
				c.OK = true
			}
		}
		want := make([]string, len(b.ASN))
		for i, a := range b.ASN {
			want[i] = fmt.Sprintf("AS%d", a)
		}
		if c.OK {
			c.Detail = fmt.Sprintf("AS%d is %s's network", asn, b.Operator)
		} else if asn == 0 {
			c.Detail = "network unknown; expected " + strings.Join(want, ", ")
		} else {
			c.Detail = fmt.Sprintf("AS%d, expected %s", asn, strings.Join(want, ", "))
		}
		if done(c) {
			return out
		}
	}

	if len(b.PTR) > 0 {
		c := m.verifyPTR(ctx, ip.String(), b.PTR)
		done(c)
	}
	return out
}

// verifyPTR does the reverse-then-forward DNS check: the PTR must land on one
// of the operator's domains and that name must resolve back to the same IP,
// so nobody can pass by pointing their own PTR record at a lookalike name.
func (m *Manager) verifyPTR(ctx context.Context, ip string, suffixes []string) Check {
	c := Check{Method: "reverse dns"}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	names, err := m.lookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		c.Detail = "no reverse DNS record"
		return c
	}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if !matchesPTR(name, suffixes) {
			c.Detail = name + " is not on " + strings.Join(suffixes, ", ")
			continue
		}
		addrs, err := m.lookupHost(ctx, name)
		if err != nil {
			c.Detail = name + " doesn't resolve forward"
			continue
		}
		for _, a := range addrs {
			if a == ip {
				c.OK, c.Detail = true, name+" → "+ip
				return c
			}
		}
		c.Detail = name + " resolves to a different IP"
	}
	return c
}

// matchesPTR: ".example.com" matches any subdomain; a pattern without a
// leading dot must match exactly.
func matchesPTR(host string, patterns []string) bool {
	for _, p := range patterns {
		p = strings.ToLower(p)
		if strings.HasPrefix(p, ".") {
			if strings.HasSuffix(host, p) {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

func (m *Manager) clearCache() {
	m.vmu.Lock()
	m.vcache = make(map[string]vEntry)
	m.vmu.Unlock()
}

func (m *Manager) sweepCache() {
	now := time.Now()
	m.vmu.Lock()
	for k, e := range m.vcache {
		if now.After(e.expires) {
			delete(m.vcache, k)
		}
	}
	m.vmu.Unlock()
}

// Explanation is the dashboard tester's answer for one IP + User-Agent.
type Explanation struct {
	Bot      *Bot    `json:"bot,omitempty"`
	Token    string  `json:"token,omitempty"`
	Checks   []Check `json:"checks"`
	Verified bool    `json:"verified"`
	Spoofed  bool    `json:"spoofed"`
	Policy   Action  `json:"policy,omitempty"` // configured action before verification
	Action   Action  `json:"action"`
	Summary  string  `json:"summary"`
}

// Explain classifies a hypothetical request, running every verification
// method fresh (bypassing the cache) and saying why.
func (m *Manager) Explain(ctx context.Context, ip net.IP, ua string) Explanation {
	st := m.state.Load()
	e := Explanation{Checks: []Check{}, Action: Standard}
	b := st.match(ua)
	if b == nil {
		e.Summary = "The User-Agent doesn't name any known bot, so the request gets standard protection."
		return e
	}
	lower := strings.ToLower(ua)
	for _, t := range st.tokens {
		if t.bot == b && strings.Contains(lower, t.s) {
			e.Token = t.s
			break
		}
	}
	e.Bot = b
	e.Policy, _ = m.actionFor(st, b)
	eff, over, unver := m.effectiveAction(st, b)
	if ip != nil && b.Verifiable() {
		e.Checks = m.verify(ctx, b, ip, true)
		for _, c := range e.Checks {
			e.Verified = e.Verified || c.OK
		}
	}
	e.Spoofed = b.Verifiable() && !e.Verified
	e.Action = e.Policy
	switch {
	case e.Policy == Block:
		e.Summary = fmt.Sprintf("Blocked: %s is set to block, and a block applies to the claim alone.", b.Name)
	case unver:
		e.Action = Block
		e.Summary = fmt.Sprintf("Blocked: %s publishes no way to verify it, and unverifiable bots are blocked, since anyone can send its User-Agent.", b.Name)
	case !b.Verifiable():
		e.Action = eff
		if over {
			e.Summary = fmt.Sprintf("%s can't be verified but is exempted with a per-bot setting, so it gets standard protection.", b.Name)
		} else {
			e.Summary = fmt.Sprintf("%s publishes no way to verify it, so the request gets standard protection.", b.Name)
		}
	case e.Verified && e.Policy == Allow:
		e.Summary = fmt.Sprintf("Verified %s — allowed straight through.", b.Name)
	case e.Verified:
		e.Summary = fmt.Sprintf("Verified %s, but it's set to standard protection.", b.Name)
	case st.policy.Spoofed == Block:
		e.Action = Block
		e.Summary = fmt.Sprintf("Claims to be %s but failed verification — spoofed claims are blocked.", b.Name)
	default:
		e.Action = Standard
		e.Summary = fmt.Sprintf("Claims to be %s but failed verification — treated as an ordinary visitor.", b.Name)
	}
	return e
}

// Directory is the dashboard's full view of bots, categories, policy and lists.
type Directory struct {
	Categories []CategoryView `json:"categories"`
	Bots       []BotView      `json:"bots"`
	Sources    []SourceStatus `json:"sources"`
	Policy     Policy         `json:"policy"`
	PolicyFile string         `json:"policy_file"`
	PolicyErr  string         `json:"policy_error,omitempty"`
}

type CategoryView struct {
	Category
	Action Action `json:"action"`
	Bots   int    `json:"bots"`
}

type BotView struct {
	*Bot
	Action     Action `json:"action"`
	Override   Action `json:"override,omitempty"`
	Verifiable bool   `json:"verifiable"`
}

func (m *Manager) Directory() Directory {
	st := m.state.Load()
	d := Directory{Policy: st.policy, PolicyFile: m.opts.PolicyFile, PolicyErr: st.loadErr}
	counts := map[string]int{}
	usedBy := map[string][]string{}
	for _, b := range st.bots {
		a, _, _ := m.effectiveAction(st, b)
		d.Bots = append(d.Bots, BotView{Bot: b, Action: a, Override: st.policy.Bots[b.ID], Verifiable: b.Verifiable()})
		counts[b.Category]++
		for _, r := range b.Ranges {
			if u := m.catalog.sourceURL(r); u != "" {
				usedBy[u] = append(usedBy[u], b.Name)
			}
		}
	}
	for _, c := range m.catalog.Categories {
		a := c.Default
		if pa, ok := st.policy.Categories[c.ID]; ok {
			a = pa
		}
		d.Categories = append(d.Categories, CategoryView{Category: c, Action: a, Bots: counts[c.ID]})
	}
	byURL := map[string]*Source{}
	for _, s := range m.catalog.Sources {
		byURL[s.URL] = s
	}
	for _, u := range m.urls() {
		rs := m.ranges.status(u)
		ss := SourceStatus{URL: u, Count: len(rs.Nets), Fetched: rs.Fetched, Tried: rs.Tried, Error: rs.Err, Bots: usedBy[u]}
		if s := byURL[u]; s != nil {
			ss.ID, ss.Operator = s.ID, s.Operator
		} else {
			ss.ID, ss.Operator = u, "Custom"
		}
		d.Sources = append(d.Sources, ss)
	}
	sort.Slice(d.Sources, func(i, j int) bool {
		if d.Sources[i].Operator != d.Sources[j].Operator {
			return d.Sources[i].Operator < d.Sources[j].Operator
		}
		return d.Sources[i].ID < d.Sources[j].ID
	})
	return d
}

// migrate builds the first policy file from the old good_bots / ai_crawlers
// settings so upgrading never changes what gets through: every bot that was
// allowed stays allowed (with its category's default where that already
// allows it), every UA that was blocked stays blocked, and a legacy entry the
// catalog doesn't know becomes a custom bot.
func (m *Manager) migrate(l *Legacy) Policy {
	p := Policy{}
	p.normalize()
	if l == nil {
		return p
	}
	// Before the catalog, SEO crawlers (semrush, ahrefsbot, dotbot, mj12bot)
	// were refused by the built-in bad-bot User-Agent list.
	p.Categories["seo"] = Block
	st := &state{byID: map[string]*Bot{}}
	for i := range m.catalog.Bots {
		b := &m.catalog.Bots[i]
		st.bots = append(st.bots, b)
		for _, t := range b.UA {
			st.tokens = append(st.tokens, token{strings.ToLower(t), b})
		}
	}
	sort.SliceStable(st.tokens, func(i, j int) bool { return len(st.tokens[i].s) > len(st.tokens[j].s) })
	// find matches a legacy entry to a catalog bot by its UA substring (either
	// way round: old configs used short tokens like "Slurp") or by name.
	find := func(name, ua string) *Bot {
		if b := st.match(ua); b != nil {
			return b
		}
		lu := strings.ToLower(ua)
		for _, b := range st.bots {
			if strings.EqualFold(b.Name, name) {
				return b
			}
			for _, t := range b.UA {
				if len(lu) >= 4 && strings.Contains(strings.ToLower(t), lu) {
					return b
				}
			}
		}
		return nil
	}
	taken := map[string]bool{}
	for _, b := range st.bots {
		taken[b.ID] = true
	}
	// addCustom keeps a legacy entry the catalog doesn't know, skipping (and
	// logging) one that wouldn't validate rather than losing the whole migration.
	addCustom := func(cb Bot, a Action) {
		base := cb.ID
		for i := 2; taken[cb.ID]; i++ {
			cb.ID = fmt.Sprintf("%s-%d", base, i)
		}
		if err := validateCustom(&cb, m.catalog, taken); err != nil {
			log.Printf("bots: legacy bot %q not migrated: %v", cb.Name, err)
			return
		}
		taken[cb.ID] = true
		p.Custom = append(p.Custom, cb)
		p.Bots[cb.ID] = a
	}
	set := func(b *Bot, a Action) {
		if c := m.catalog.category(b.Category); c != nil && c.Default == a {
			return
		}
		p.Bots[b.ID] = a
	}
	for _, lb := range l.Allow {
		if b := find(lb.Name, lb.UAContains); b != nil {
			set(b, Allow)
			continue
		}
		if len(lb.ValidPTR) == 0 {
			log.Printf("bots: legacy bot %q has no reverse DNS rule and isn't in the catalog; not migrated", lb.Name)
			continue
		}
		addCustom(Bot{ID: slug(lb.Name), Name: lb.Name, Category: "search", UA: []string{lb.UAContains}, PTR: append([]string{}, lb.ValidPTR...)}, Allow)
	}
	for _, ua := range l.Block {
		if b := find(ua, ua); b != nil {
			set(b, Block)
			continue
		}
		addCustom(Bot{ID: slug(ua), Name: ua, Category: "ai_training", UA: []string{ua}}, Block)
	}
	if v, err := p.validate(m.catalog); err == nil {
		return v
	} else {
		log.Printf("bots: migrated policy invalid (%v); starting from defaults", err)
	}
	p = Policy{}
	p.normalize()
	return p
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) < 2 {
		out = "custom-" + out
	}
	if len(out) > 48 {
		out = out[:48]
	}
	return out
}
