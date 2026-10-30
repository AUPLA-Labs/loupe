package rules

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

// env is the world a request is evaluated in: the values the lazy facts
// return, and how many times each was asked for.
type env struct {
	asn        uint
	asnOK      bool
	datacenter bool
	dcUnknown  bool // Facts.Datacenter reports the fact as unknown
	country    string
	noCountry  bool // leave Facts.Country nil
	network    Network
	noNetwork  bool // leave Facts.Network nil
	badIP      int
	bot        string
	cleared    bool

	calls struct{ asn, datacenter, country, network, badIP, bot, cleared int }
}

// facts builds Facts for r with counting stubs for every lazy func.
func (e *env) facts(r *http.Request, ip string) *Facts {
	f := &Facts{
		Req:        r,
		IP:         net.ParseIP(ip),
		ClientKey:  ip,
		Now:        time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC),
		ASN:        func() (uint, bool) { e.calls.asn++; return e.asn, e.asnOK },
		Datacenter: func() (bool, bool) { e.calls.datacenter++; return e.datacenter, !e.dcUnknown },
		BadIP:      func() int { e.calls.badIP++; return e.badIP },
		Bot:        func() string { e.calls.bot++; return e.bot },
		Cleared:    func() bool { e.calls.cleared++; return e.cleared },
	}
	if !e.noCountry {
		f.Country = func() string { e.calls.country++; return e.country }
	}
	if !e.noNetwork {
		f.Network = func() Network { e.calls.network++; return e.network }
	}
	return f
}

// probe describes one request and the world around it.
type probe struct {
	method string
	target string
	host   string // "" keeps httptest's example.com
	ua     string
	ip     string // "" = 198.51.100.7
	hdr    [][2]string
	env    env
}

func (p probe) run(t *testing.T, s *Set) (*Hit, []string, *env) {
	t.Helper()
	r := newProbeRequest(p)
	ip := p.ip
	if ip == "" {
		ip = "198.51.100.7"
	}
	e := p.env
	hit, logged := s.Evaluate(e.facts(r, ip))
	return hit, logged, &e
}

// newProbeRequest builds the request p describes.
func newProbeRequest(p probe) *http.Request {
	method := p.method
	if method == "" {
		method = "GET"
	}
	target := p.target
	if target == "" {
		target = "/"
	}
	r := httptest.NewRequest(method, target, nil)
	if p.host != "" {
		r.Host = p.host
	}
	if p.ua != "" {
		r.Header.Set("User-Agent", p.ua)
	}
	for _, kv := range p.hdr {
		r.Header.Add(kv[0], kv[1])
	}
	return r
}

// enforce wraps m in an enforced block rule.
func enforce(id string, m Match) Rule {
	return Rule{ID: id, Mode: ModeEnforce, Action: ActionBlock, Match: m}
}

func mustCompile(t *testing.T, rs ...Rule) *Set {
	t.Helper()
	s, errs := Compile(rs)
	if errs != nil {
		t.Fatalf("Compile: %v", errs)
	}
	return s
}

func yes(b bool) *bool { return &b }

func TestMatchFields(t *testing.T) {
	tests := []struct {
		name  string
		match Match
		hit   probe
		miss  probe
	}{
		{"ipv4 cidr", Match{IPs: []string{"203.0.113.0/24"}},
			probe{ip: "203.0.113.9"}, probe{ip: "203.0.114.9"}},
		{"ipv4 address", Match{IPs: []string{"203.0.113.9"}},
			probe{ip: "203.0.113.9"}, probe{ip: "203.0.113.10"}},
		{"ipv6 address", Match{IPs: []string{"2001:db8::1"}},
			probe{ip: "2001:db8::1"}, probe{ip: "2001:db8::2"}},
		{"ipv6 cidr", Match{IPs: []string{"2001:db8::/32"}},
			probe{ip: "2001:db8:1::5"}, probe{ip: "2001:db9::1"}},
		{"asn", Match{ASNs: []uint{64496, 64497}},
			probe{env: env{asn: 64497, asnOK: true}}, probe{env: env{asn: 64498, asnOK: true}}},
		{"asn unknown never matches", Match{ASNs: []uint{64496}},
			probe{env: env{asn: 64496, asnOK: true}}, probe{env: env{asn: 64496, asnOK: false}}},
		{"host wildcard subdomain", Match{Hosts: []string{"*.example.com"}},
			probe{host: "a.example.com"}, probe{host: "example.com"}},
		{"host exact", Match{Hosts: []string{"example.com"}},
			probe{host: "example.com"}, probe{host: "a.example.com"}},
		{"host with port", Match{Hosts: []string{"example.com"}},
			probe{host: "example.com:443"}, probe{host: "example.org:443"}},
		{"host upper case", Match{Hosts: []string{"example.com"}},
			probe{host: "EXAMPLE.com"}, probe{host: "other.com"}},
		{"wildcard host with port", Match{Hosts: []string{"*.example.com"}},
			probe{host: "A.Example.com:8443"}, probe{host: "example.com:8443"}},
		{"host with trailing dot", Match{Hosts: []string{"example.com"}},
			probe{host: "example.com."}, probe{host: "example.com.."}},
		{"host with trailing dot and port", Match{Hosts: []string{"*.example.com"}},
			probe{host: "a.example.com.:443"}, probe{host: "example.com.:443"}},
		{"ipv6 literal host", Match{Hosts: []string{"[::1]"}},
			probe{host: "[::1]:8080"}, probe{host: "[::2]:8080"}},
		{"method", Match{Methods: []string{"post"}},
			probe{method: "POST"}, probe{method: "GET"}},
		{"path prefix", Match{Paths: []PathMatch{{Prefix: "/api/"}}},
			probe{target: "/api/v1"}, probe{target: "/app"}},
		{"path exact", Match{Paths: []PathMatch{{Exact: "/login"}}},
			probe{target: "/login"}, probe{target: "/login/x"}},
		{"path glob", Match{Paths: []PathMatch{{Glob: "/static/*.js"}}},
			probe{target: "/static/a/b.js"}, probe{target: "/static/a.css"}},
		{"path glob question mark", Match{Paths: []PathMatch{{Glob: "/v?/x"}}},
			probe{target: "/v2/x"}, probe{target: "/v22/x"}},
		{"path regex", Match{Paths: []PathMatch{{Regex: `^/v[0-9]+/`}}},
			probe{target: "/v12/x"}, probe{target: "/vx/x"}},
		{"path ignores query string", Match{Paths: []PathMatch{{Exact: "/p"}}},
			probe{target: "/p?a=1"}, probe{target: "/q?/p"}},
		{"path any of several", Match{Paths: []PathMatch{{Exact: "/a"}, {Prefix: "/b"}}},
			probe{target: "/b/c"}, probe{target: "/c"}},
		{"user agent glob", Match{UserAgents: []PathMatch{{Glob: "*/admin*"}}},
			probe{ua: "scanner/admin-probe 1.0"}, probe{ua: "Mozilla/5.0"}},
		{"user agent prefix", Match{UserAgents: []PathMatch{{Prefix: "curl/"}}},
			probe{ua: "curl/8.5"}, probe{ua: "Mozilla curl/8.5"}},
		{"countries", Match{Countries: []string{"nl", "de"}},
			probe{env: env{country: "DE"}}, probe{env: env{country: "US"}}},
		{"countries unknown", Match{Countries: []string{"de"}},
			probe{env: env{country: "DE"}}, probe{env: env{country: ""}}},
		{"registered countries", Match{RegisteredCountries: []string{"us"}},
			probe{env: env{network: Network{RegisteredCountry: "US"}}}, probe{env: env{network: Network{RegisteredCountry: "DE"}}}},
		{"network types", Match{NetworkTypes: []string{"hosting", "business"}},
			probe{env: env{network: Network{Type: "hosting"}}}, probe{env: env{network: Network{Type: "isp"}}}},
		{"network roles", Match{NetworkRoles: []string{"stub"}},
			probe{env: env{network: Network{Role: "stub"}}}, probe{env: env{network: Network{Role: "tier1_transit"}}}},
		{"classes any of", Match{Classes: []string{"tor_exit", "vpn"}},
			probe{env: env{network: Network{Classes: []string{"vpn", "hosting"}}}}, probe{env: env{network: Network{Classes: []string{"hosting"}}}}},
		{"classes none", Match{Classes: []string{"vpn"}},
			probe{env: env{network: Network{Classes: []string{"vpn"}}}}, probe{env: env{network: Network{}}}},
		{"lists", Match{Lists: []string{"mullvad"}},
			probe{env: env{network: Network{List: "mullvad"}}}, probe{env: env{network: Network{List: "protonvpn"}}}},
		{"network unknown", Match{NetworkTypes: []string{"hosting"}},
			probe{env: env{network: Network{Type: "hosting"}}}, probe{env: env{network: Network{Type: "hosting"}, noNetwork: true}}},
		{"network and country together", Match{Classes: []string{"vpn"}, Countries: []string{"RU"}},
			probe{env: env{country: "RU", network: Network{Classes: []string{"vpn"}}}}, probe{env: env{country: "DE", network: Network{Classes: []string{"vpn"}}}}},
		{"datacenter true", Match{Datacenter: yes(true)},
			probe{env: env{datacenter: true}}, probe{env: env{datacenter: false}}},
		{"datacenter true unknown", Match{Datacenter: yes(true)},
			probe{env: env{datacenter: true}}, probe{env: env{datacenter: true, dcUnknown: true}}},
		{"datacenter false unknown", Match{Datacenter: yes(false)},
			probe{env: env{datacenter: false}}, probe{env: env{datacenter: false, dcUnknown: true}}},
		{"datacenter false", Match{Datacenter: yes(false)},
			probe{env: env{datacenter: false}}, probe{env: env{datacenter: true}}},
		{"bad ip at least", Match{BadIPAtLeast: 50},
			probe{env: env{badIP: 50}}, probe{env: env{badIP: 49}}},
		{"bots", Match{Bots: []string{"googlebot", "bingbot"}},
			probe{env: env{bot: "bingbot"}}, probe{env: env{bot: ""}}},
		{"bots other bot", Match{Bots: []string{"googlebot"}},
			probe{env: env{bot: "googlebot"}}, probe{env: env{bot: "bingbot"}}},
		{"cleared true", Match{Cleared: yes(true)},
			probe{env: env{cleared: true}}, probe{env: env{cleared: false}}},
		{"cleared false", Match{Cleared: yes(false)},
			probe{env: env{cleared: false}}, probe{env: env{cleared: true}}},
		{"header", Match{Headers: []HeaderMatch{{Name: "X-Foo", Op: "equals", Value: "1"}}},
			probe{hdr: [][2]string{{"X-Foo", "1"}}}, probe{hdr: [][2]string{{"X-Foo", "2"}}}},
		{"query", Match{Query: []HeaderMatch{{Name: "q", Op: "present"}}},
			probe{target: "/?q="}, probe{target: "/?p=1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mustCompile(t, enforce("r1", tt.match))
			if hit, _, _ := tt.hit.run(t, s); hit == nil || hit.ID != "r1" || hit.Action != ActionBlock {
				t.Errorf("matching request: hit = %+v, want rule r1 with block", hit)
			}
			if hit, logged, _ := tt.miss.run(t, s); hit != nil || len(logged) != 0 {
				t.Errorf("non-matching request: hit = %+v, logged = %v, want nothing", hit, logged)
			}
		})
	}
}

func TestHitCarriesChallengeTier(t *testing.T) {
	s := mustCompile(t, Rule{ID: "ask", Mode: ModeEnforce, Action: ActionChallenge, Tier: "prism",
		Match: Match{Paths: []PathMatch{{Prefix: "/"}}}})
	hit, _, _ := probe{}.run(t, s)
	if hit == nil || hit.Action != ActionChallenge || hit.Tier != tier.Prism {
		t.Fatalf("hit = %+v, want challenge at prism", hit)
	}
}

func TestHeaderAndQueryOps(t *testing.T) {
	// Each row is run against a header test and a query test. The request
	// has "X-Foo: a" and "X-Foo: b" (and ?q=1&q=2), and the rule spells the
	// name in a different case from the one the request used.
	ops := []struct {
		name string
		op   string
		val  string
		want bool
	}{
		{"present", "present", "", true},
		{"absent", "absent", "", false},
		{"equals first value", "equals", "a", true},
		{"equals second value", "equals", "b", true},
		{"equals no value", "equals", "c", false},
		{"equals is case sensitive", "equals", "A", false},
		{"contains", "contains", "a", true},
		{"contains no value", "contains", "zz", false},
		{"contains is case sensitive", "contains", "B", false},
		{"regex", "regex", "^b$", true},
		{"regex no value", "regex", "^c$", false},
	}

	type kind struct {
		name     string
		nameCase string
		probe    probe
		match    func(HeaderMatch) Match
	}
	kinds := []kind{
		{"header", "x-FOO", probe{hdr: [][2]string{{"X-Foo", "a"}, {"X-Foo", "b"}}},
			func(h HeaderMatch) Match { return Match{Headers: []HeaderMatch{h}} }},
		{"query", "x", probe{target: "/?x=a&x=b"},
			func(h HeaderMatch) Match { return Match{Query: []HeaderMatch{h}} }},
	}
	for _, k := range kinds {
		for _, o := range ops {
			t.Run(k.name+"/"+o.name, func(t *testing.T) {
				h := HeaderMatch{Name: k.nameCase, Op: o.op, Value: o.val}
				s := mustCompile(t, enforce("r1", k.match(h)))
				hit, _, _ := k.probe.run(t, s)
				if got := hit != nil; got != o.want {
					t.Errorf("%s %s %q on repeated field: matched = %v, want %v", k.name, o.op, o.val, got, o.want)
				}
			})
		}
	}

	t.Run("query repeated numeric values", func(t *testing.T) {
		s := mustCompile(t, enforce("r1", Match{Query: []HeaderMatch{{Name: "q", Op: "equals", Value: "2"}}}))
		if hit, _, _ := (probe{target: "/?q=1&q=2"}).run(t, s); hit == nil {
			t.Error("?q=1&q=2 should satisfy q equals 2")
		}
		if hit, _, _ := (probe{target: "/?q=1&q=3"}).run(t, s); hit != nil {
			t.Error("?q=1&q=3 should not satisfy q equals 2")
		}
	})

	missing := []struct {
		name string
		op   string
		val  string
		want bool
	}{
		{"present", "present", "", false},
		{"absent", "absent", "", true},
		{"equals", "equals", "a", false},
		{"contains", "contains", "a", false},
		{"regex", "regex", ".", false},
	}
	for _, o := range missing {
		t.Run("missing header/"+o.name, func(t *testing.T) {
			s := mustCompile(t, enforce("r1", Match{Headers: []HeaderMatch{{Name: "X-Foo", Op: o.op, Value: o.val}}}))
			hit, _, _ := probe{}.run(t, s)
			if got := hit != nil; got != o.want {
				t.Errorf("header %s on a request without it: matched = %v, want %v", o.op, got, o.want)
			}
		})
		t.Run("missing query/"+o.name, func(t *testing.T) {
			s := mustCompile(t, enforce("r1", Match{Query: []HeaderMatch{{Name: "q", Op: o.op, Value: o.val}}}))
			hit, _, _ := (probe{target: "/?other=1"}).run(t, s)
			if got := hit != nil; got != o.want {
				t.Errorf("query %s on a request without it: matched = %v, want %v", o.op, got, o.want)
			}
		})
	}

	t.Run("any listed test may succeed", func(t *testing.T) {
		s := mustCompile(t, enforce("r1", Match{Headers: []HeaderMatch{
			{Name: "X-Nope", Op: "present"},
			{Name: "X-Foo", Op: "equals", Value: "b"},
		}}))
		hit, _, _ := (probe{hdr: [][2]string{{"X-Foo", "a"}, {"X-Foo", "b"}}}).run(t, s)
		if hit == nil {
			t.Error("second header test should satisfy the field")
		}
	})

	t.Run("name sent in lower case is not canonical", func(t *testing.T) {
		// net/http canonicalises names when it parses a request, so a
		// non-canonical key in r.Header only arises from code that assigns
		// the map directly. Evaluate reads Header[canonical] as is (it does
		// not scan or canonicalise per request), and this pins that choice.
		s := mustCompile(t, enforce("r1", Match{Headers: []HeaderMatch{{Name: "x-foo", Op: "present"}}}))
		r := httptest.NewRequest("GET", "/", nil)
		r.Header["x-foo"] = []string{"a"}
		var e env
		if hit, _ := s.Evaluate(e.facts(r, "198.51.100.7")); hit != nil {
			t.Errorf("hit = %+v; a non-canonical key assigned directly must not be found", hit)
		}
		r.Header["X-Foo"] = []string{"a"}
		if hit, _ := s.Evaluate(e.facts(r, "198.51.100.7")); hit == nil {
			t.Error("the canonical key should be found")
		}
	})
}

func TestHostHeaderTest(t *testing.T) {
	// Go moves Host out of r.Header into r.Host, so a header test named Host
	// has to read r.Host.
	tests := []struct {
		name string
		h    HeaderMatch
		host string
		want bool
	}{
		{"equals", HeaderMatch{Name: "Host", Op: "equals", Value: "api.example.com"}, "api.example.com", true},
		{"equals other", HeaderMatch{Name: "Host", Op: "equals", Value: "api.example.com"}, "www.example.com", false},
		{"lower case name", HeaderMatch{Name: "host", Op: "contains", Value: "example"}, "api.example.com", true},
		{"present", HeaderMatch{Name: "Host", Op: "present"}, "api.example.com", true},
		{"absent", HeaderMatch{Name: "Host", Op: "absent"}, "api.example.com", false},
		{"regex", HeaderMatch{Name: "Host", Op: "regex", Value: `^api\.`}, "api.example.com", true},
		{"keeps port", HeaderMatch{Name: "Host", Op: "equals", Value: "api.example.com:8443"}, "api.example.com:8443", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mustCompile(t, enforce("r1", Match{Headers: []HeaderMatch{tt.h}}))
			hit, _, _ := (probe{host: tt.host}).run(t, s)
			if got := hit != nil; got != tt.want {
				t.Errorf("Host %s %q against %q: matched = %v, want %v", tt.h.Op, tt.h.Value, tt.host, got, tt.want)
			}
		})
	}
}

func TestFieldsAndTogether(t *testing.T) {
	s := mustCompile(t, enforce("r1", Match{
		Paths:   []PathMatch{{Prefix: "/admin"}},
		Methods: []string{"POST"},
	}))
	tests := []struct {
		name string
		p    probe
		want bool
	}{
		{"both match", probe{method: "POST", target: "/admin/x"}, true},
		{"path only", probe{method: "GET", target: "/admin/x"}, false},
		{"method only", probe{method: "POST", target: "/home"}, false},
		{"neither", probe{method: "GET", target: "/home"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit, _, _ := tt.p.run(t, s)
			if got := hit != nil; got != tt.want {
				t.Errorf("matched = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExceptSuppressesHit(t *testing.T) {
	r := enforce("r1", Match{Paths: []PathMatch{{Prefix: "/api/"}}})
	r.Except = &Match{IPs: []string{"203.0.113.0/24"}, Methods: []string{"GET"}}
	s := mustCompile(t, r)

	tests := []struct {
		name string
		p    probe
		want bool
	}{
		{"match, no except", probe{target: "/api/x", ip: "198.51.100.7"}, true},
		{"except ip but not method", probe{method: "POST", target: "/api/x", ip: "203.0.113.5"}, true},
		{"except method but not ip", probe{target: "/api/x", ip: "198.51.100.7"}, true},
		{"except holds", probe{target: "/api/x", ip: "203.0.113.5"}, false},
		{"no match", probe{target: "/web", ip: "198.51.100.7"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// except fields AND together just like match fields
			hit, _, _ := tt.p.run(t, s)
			if got := hit != nil; got != tt.want {
				t.Errorf("matched = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFirstEnforceHitWins(t *testing.T) {
	first := enforce("first", Match{Paths: []PathMatch{{Prefix: "/"}}})
	second := enforce("second", Match{Paths: []PathMatch{{Prefix: "/"}}, ASNs: []uint{64496}})
	second.Action = ActionAllow
	s := mustCompile(t, first, second)

	hit, _, e := probe{env: env{asn: 64496, asnOK: true}}.run(t, s)
	if hit == nil || hit.ID != "first" || hit.Action != ActionBlock {
		t.Fatalf("hit = %+v, want first", hit)
	}
	if e.calls.asn != 0 {
		t.Errorf("ASN() called %d times; the second rule must not be evaluated after a hit", e.calls.asn)
	}
}

func TestLogModeNeverEnforces(t *testing.T) {
	all := Match{Paths: []PathMatch{{Prefix: "/"}}}
	s := mustCompile(t,
		Rule{ID: "log-mode-block", Mode: ModeLog, Action: ActionBlock, Match: all},
		Rule{ID: "default-mode", Action: ActionBlock, Match: all}, // no mode means log
		Rule{ID: "log-action", Mode: ModeEnforce, Action: ActionLog, Match: all},
		Rule{ID: "no-match", Mode: ModeEnforce, Action: ActionBlock, Match: Match{Paths: []PathMatch{{Exact: "/nope"}}}},
		Rule{ID: "real", Mode: ModeEnforce, Action: ActionBlock, Match: all},
		Rule{ID: "after", Mode: ModeLog, Action: ActionBlock, Match: all},
	)
	hit, logged, _ := probe{}.run(t, s)
	if hit == nil || hit.ID != "real" {
		t.Fatalf("hit = %+v, want real", hit)
	}
	want := []string{"log-mode-block", "default-mode", "log-action"}
	if fmt.Sprint(logged) != fmt.Sprint(want) {
		t.Errorf("logged = %v, want %v in file order and without rules after the hit", logged, want)
	}

	// Without an enforcing rule there is no hit at all.
	s = mustCompile(t,
		Rule{ID: "a", Mode: ModeLog, Action: ActionBlock, Match: all},
		Rule{ID: "b", Mode: ModeEnforce, Action: ActionLog, Match: all},
	)
	hit, logged, _ = probe{}.run(t, s)
	if hit != nil {
		t.Errorf("hit = %+v, want none when every match is log-only", hit)
	}
	if fmt.Sprint(logged) != "[a b]" {
		t.Errorf("logged = %v, want [a b]", logged)
	}
}

func TestExpiredRuleInactive(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		expires time.Time
		want    bool
	}{
		{"before now", now.Add(-time.Second), false},
		{"equal to now", now, false},
		{"after now", now.Add(time.Second), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := enforce("r1", Match{Paths: []PathMatch{{Prefix: "/"}}})
			exp := tt.expires
			r.Expires = &exp
			s := mustCompile(t, r)
			hit, _, _ := probe{}.run(t, s) // facts use the same fixed Now
			if got := hit != nil; got != tt.want {
				t.Errorf("expires %v, now %v: matched = %v, want %v", tt.expires, now, got, tt.want)
			}
		})
	}

	t.Run("zero Now uses the wall clock", func(t *testing.T) {
		past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
		a := enforce("old", Match{Paths: []PathMatch{{Prefix: "/"}}})
		a.Expires = &past
		b := enforce("fresh", Match{Paths: []PathMatch{{Prefix: "/"}}})
		b.Expires = &future
		s := mustCompile(t, a, b)
		var e env
		f := e.facts(httptest.NewRequest("GET", "/", nil), "198.51.100.7")
		f.Now = time.Time{}
		hit, _ := s.Evaluate(f)
		if hit == nil || hit.ID != "fresh" {
			t.Errorf("hit = %+v, want fresh (old expired an hour ago)", hit)
		}
	})
}

func TestDisabledRuleInactive(t *testing.T) {
	off := enforce("off", Match{Paths: []PathMatch{{Prefix: "/"}}})
	off.Enabled = yes(false)
	offLog := Rule{ID: "off-log", Enabled: yes(false), Action: ActionLog, Match: Match{Paths: []PathMatch{{Prefix: "/"}}}}
	on := enforce("on", Match{Paths: []PathMatch{{Prefix: "/"}}})
	on.Enabled = yes(true)
	s := mustCompile(t, off, offLog, on)
	hit, logged, _ := probe{}.run(t, s)
	if hit == nil || hit.ID != "on" {
		t.Errorf("hit = %+v, want on", hit)
	}
	if len(logged) != 0 {
		t.Errorf("logged = %v, want none from a disabled rule", logged)
	}
}

func TestASNLookupSkippedWhenUnused(t *testing.T) {
	var rs []Rule
	for i := 0; i < 50; i++ {
		rs = append(rs, enforce(fmt.Sprintf("p%d", i), Match{
			Paths: []PathMatch{{Exact: fmt.Sprintf("/never-%d", i)}},
		}))
	}
	// An ASN rule that fails on a cheap field first must not look up either.
	rs = append(rs, enforce("cheap-first", Match{Paths: []PathMatch{{Exact: "/other"}}, ASNs: []uint{1}, Datacenter: yes(true)}))
	s := mustCompile(t, rs...)

	hit, _, e := probe{env: env{asn: 64496, asnOK: true}}.run(t, s)
	if hit != nil {
		t.Fatalf("hit = %+v, want none", hit)
	}
	if e.calls.asn != 0 || e.calls.datacenter != 0 {
		t.Errorf("lazy calls = %+v, want none when no rule reached an ASN or datacenter test", e.calls)
	}

	// Several rules that need the ASN: the lookup still happens once.
	rs = append(rs,
		enforce("asn-a", Match{ASNs: []uint{111}}),
		enforce("asn-b", Match{ASNs: []uint{222}}),
		Rule{ID: "asn-except", Mode: ModeEnforce, Action: ActionBlock,
			Match:  Match{Paths: []PathMatch{{Prefix: "/"}}},
			Except: &Match{ASNs: []uint{333}}},
	)
	s = mustCompile(t, rs...)
	hit, _, e = probe{env: env{asn: 222, asnOK: true}}.run(t, s)
	if hit == nil || hit.ID != "asn-b" {
		t.Fatalf("hit = %+v, want asn-b", hit)
	}
	if e.calls.asn != 1 {
		t.Errorf("ASN() called %d times, want exactly 1", e.calls.asn)
	}

	// Same when nothing matches and every ASN rule is consulted.
	hit, _, e = probe{env: env{asn: 999, asnOK: true}}.run(t, s)
	if hit == nil || hit.ID != "asn-except" {
		t.Fatalf("hit = %+v, want asn-except", hit)
	}
	if e.calls.asn != 1 {
		t.Errorf("ASN() called %d times across three ASN tests, want exactly 1", e.calls.asn)
	}
}

func TestLazyFactsMemoised(t *testing.T) {
	m := Match{
		Datacenter:   yes(false),
		BadIPAtLeast: 100,
		Bots:         []string{"nobot"},
		Cleared:      yes(true),
		Countries:    []string{"ZZ"},
	}
	// Five rules all consult every lazy fact, and none of them matches.
	var rs []Rule
	for i := 0; i < 5; i++ {
		rs = append(rs, enforce(fmt.Sprintf("r%d", i), m))
	}
	s := mustCompile(t, rs...)
	// Use a world where every field passes, so each rule reaches every fact.
	hit, _, e := probe{env: env{datacenter: false, badIP: 100, bot: "nobot", cleared: true, country: "ZZ"}}.run(t, s)
	if hit == nil {
		t.Fatal("expected the first rule to hit")
	}
	if c := e.calls; c.country != 1 || c.datacenter != 1 || c.badIP != 1 || c.bot != 1 || c.cleared != 1 {
		t.Errorf("calls after a full match = %+v, want one each", c)
	}

	// Now make every rule fail at the last field (bots) so all five are consulted.
	hit, _, e = probe{env: env{datacenter: false, badIP: 100, bot: "other", cleared: true, country: "ZZ"}}.run(t, s)
	if hit != nil {
		t.Fatalf("hit = %+v, want none", hit)
	}
	if c := e.calls; c.country != 1 || c.datacenter != 1 || c.badIP != 1 || c.bot != 1 || c.cleared != 1 {
		t.Errorf("calls across five failing rules = %+v, want one each", c)
	}
}

func TestCheapLazyFactsBeforeBotLookup(t *testing.T) {
	// Bot() can mean a DNS check, so every other lazy fact is tried first.
	s := mustCompile(t, enforce("r1", Match{Bots: []string{"x"}, Cleared: yes(false)}))
	hit, _, e := probe{env: env{bot: "x", cleared: true}}.run(t, s)
	if hit != nil {
		t.Fatalf("hit = %+v, want none: the client is cleared", hit)
	}
	if e.calls.bot != 0 {
		t.Errorf("Bot() called %d times; cleared=false already failed the rule", e.calls.bot)
	}

	s = mustCompile(t, enforce("r2", Match{Bots: []string{"x"}, Datacenter: yes(true), ASNs: []uint{7}, BadIPAtLeast: 5, Countries: []string{"NL"}}))
	hit, _, e = probe{env: env{bot: "x", country: "NL", asn: 7, asnOK: true, datacenter: true, badIP: 4}}.run(t, s)
	if hit != nil || e.calls.bot != 0 {
		t.Errorf("hit = %+v, Bot() calls = %d; want none and 0 when bad_ip fails", hit, e.calls.bot)
	}
}

func TestLazyFactsNilMeansUnknown(t *testing.T) {
	tests := []struct {
		name  string
		match Match
	}{
		{"asn", Match{ASNs: []uint{1}}},
		{"datacenter", Match{Datacenter: yes(false)}},
		{"bad ip", Match{BadIPAtLeast: 1}},
		{"bots", Match{Bots: []string{"googlebot"}}},
		{"cleared", Match{Cleared: yes(false)}},
		{"countries", Match{Countries: []string{"NL"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mustCompile(t, enforce("r1", tt.match))
			f := &Facts{Req: httptest.NewRequest("GET", "/", nil), IP: net.ParseIP("198.51.100.7")}
			if hit, logged := s.Evaluate(f); hit != nil || len(logged) != 0 {
				t.Errorf("hit = %+v, logged = %v; a rule needing an unavailable fact must not match", hit, logged)
			}
		})
	}

	t.Run("in except", func(t *testing.T) {
		// An unknown fact in except is "does not match", so the rule still hits.
		r := enforce("r1", Match{Paths: []PathMatch{{Prefix: "/"}}})
		r.Except = &Match{ASNs: []uint{1}}
		s := mustCompile(t, r)
		f := &Facts{Req: httptest.NewRequest("GET", "/", nil), IP: net.ParseIP("198.51.100.7")}
		if hit, _ := s.Evaluate(f); hit == nil {
			t.Error("rule should hit when its except needs an unknown fact")
		}
	})
}

func TestCountryRuleInertWithoutSource(t *testing.T) {
	s := mustCompile(t, enforce("nl", Match{Countries: []string{"NL"}}))
	hit, _, e := probe{env: env{country: "NL", noCountry: true}}.run(t, s)
	if hit != nil {
		t.Errorf("hit = %+v, want none: with no country source the rule never matches", hit)
	}
	if e.calls.country != 0 {
		t.Errorf("country called %d times with a nil source", e.calls.country)
	}
	// With a source, the same rule works.
	hit, _, _ = probe{env: env{country: "NL"}}.run(t, s)
	if hit == nil {
		t.Error("rule should match when the source reports NL")
	}
}

func TestQueryParsedOnlyWhenNeeded(t *testing.T) {
	// Several rules share one query string; a malformed pair must not break
	// the others; and with no query test in the set nothing is parsed (which
	// would allocate).
	s := mustCompile(t,
		enforce("a", Match{Query: []HeaderMatch{{Name: "a", Op: "equals", Value: "1"}}}),
		enforce("b", Match{Query: []HeaderMatch{{Name: "b", Op: "equals", Value: "2"}}}),
	)
	hit, _, _ := (probe{target: "/?a=0&b=2"}).run(t, s)
	if hit == nil || hit.ID != "b" {
		t.Errorf("hit = %+v, want b", hit)
	}
	// A malformed query: the readable pairs still count.
	hit, _, _ = (probe{target: "/?a=1&b=%zz"}).run(t, s)
	if hit == nil || hit.ID != "a" {
		t.Errorf("hit = %+v, want a despite the malformed pair", hit)
	}

	// No rule has a query test: evaluation must not allocate for it.
	s = mustCompile(t, enforce("p", Match{Paths: []PathMatch{{Exact: "/nope"}}}))
	var e env
	f := e.facts(httptest.NewRequest("GET", "/?a=1&b=2&c=3", nil), "198.51.100.7")
	if n := testing.AllocsPerRun(100, func() { s.Evaluate(f) }); n != 0 {
		t.Errorf("Evaluate allocated %v times with no query rules, want 0", n)
	}
}

func TestNilSetEvaluatesNothing(t *testing.T) {
	var s *Set
	var e env
	hit, logged := s.Evaluate(e.facts(httptest.NewRequest("GET", "/", nil), "198.51.100.7"))
	if hit != nil || logged != nil {
		t.Errorf("nil set: hit = %+v, logged = %v, want nothing", hit, logged)
	}
	empty := mustCompile(t)
	hit, logged = empty.Evaluate(e.facts(httptest.NewRequest("GET", "/", nil), "198.51.100.7"))
	if hit != nil || logged != nil {
		t.Errorf("empty set: hit = %+v, logged = %v, want nothing", hit, logged)
	}
}

func TestEvaluateDoesNotAllocateWhenNothingMatches(t *testing.T) {
	s := mustCompile(t,
		enforce("ip", Match{IPs: []string{"203.0.113.0/24"}}),
		enforce("host", Match{Hosts: []string{"Other.Test", "*.Other.Test"}}),
		enforce("ua", Match{UserAgents: []PathMatch{{Glob: "*scrapy*"}, {Regex: "^bad"}}}),
		enforce("hdr", Match{Headers: []HeaderMatch{{Name: "x-a", Op: "equals", Value: "1"}, {Name: "host", Op: "equals", Value: "x"}}}),
		enforce("asn", Match{ASNs: []uint{1}}),
	)
	var e env
	r := httptest.NewRequest("GET", "/index", nil)
	r.Host = "Site.Test:8443"
	r.Header.Set("User-Agent", "Mozilla/5.0")
	f := e.facts(r, "198.51.100.7")
	if n := testing.AllocsPerRun(100, func() { s.Evaluate(f) }); n != 0 {
		t.Errorf("Evaluate allocated %v times for a request matching nothing, want 0", n)
	}
}

// benchRules builds 500 rules in a realistic mix that never match benchReq:
// IPs and CIDRs, paths of every kind, user agents (plain globs, multi-segment
// globs and unanchored regexes), header tests including regexes, hosts, rules
// with an except, query rules, and a few ASN and datacenter rules at the end.
func benchRules() []Rule {
	rs := make([]Rule, 0, 500)
	add := func(m Match) {
		rs = append(rs, enforce(fmt.Sprintf("bench-%d", len(rs)), m))
	}
	for i := 0; i < 135; i++ { // IPs and CIDRs
		switch i % 3 {
		case 0:
			add(Match{IPs: []string{fmt.Sprintf("203.0.%d.0/24", i)}})
		case 1:
			add(Match{IPs: []string{fmt.Sprintf("192.0.2.%d", i), fmt.Sprintf("2001:db8:%x::/48", i)}})
		default:
			add(Match{IPs: []string{fmt.Sprintf("100.%d.0.0/16", 64+i%64)}})
		}
	}
	for i := 0; i < 115; i++ { // paths
		switch i % 5 {
		case 0:
			add(Match{Paths: []PathMatch{{Prefix: fmt.Sprintf("/private-%d/", i)}}})
		case 1:
			add(Match{Paths: []PathMatch{{Exact: fmt.Sprintf("/exact-%d.php", i)}}})
		case 2:
			add(Match{Paths: []PathMatch{{Glob: fmt.Sprintf("/wp-%d/*.php", i)}}})
		case 3:
			add(Match{Paths: []PathMatch{{Glob: fmt.Sprintf("/a%d/*/b*/c", i)}}})
		default:
			if i%10 == 4 {
				add(Match{Paths: []PathMatch{{Regex: fmt.Sprintf(`^/old-%d/(admin|login)\.php$`, i)}}})
			} else {
				add(Match{Paths: []PathMatch{{Prefix: fmt.Sprintf("/internal-%d", i)}}})
			}
		}
	}
	for i := 0; i < 77; i++ { // plain user agent globs
		if i%10 == 9 {
			add(Match{UserAgents: []PathMatch{{Glob: fmt.Sprintf("bot%d-*", i)}}})
		} else {
			add(Match{UserAgents: []PathMatch{{Glob: fmt.Sprintf("*badword%d*", i)}}})
		}
	}
	for i := 0; i < 15; i++ { // multi-segment user agent globs
		add(Match{UserAgents: []PathMatch{{Glob: fmt.Sprintf("*scrapy%d*bot*", i)}}})
	}
	uaRegexes := []string{
		`(?i)python-requests|scrapy`, `(?i)(curl|wget|libwww)/[0-9]`, `(?i)headless(chrome)?`,
		`(?i)\b(spider|crawler)\b`, `(?i)go-http-client/[0-9.]+`, `(?i)java/1\.[0-9]`,
		`(?i)(ahrefs|semrush|mj12)bot`, `(?i)okhttp|httpclient`,
	}
	for _, re := range uaRegexes { // unanchored user agent regexes
		add(Match{UserAgents: []PathMatch{{Regex: re}}})
	}
	for i := 0; i < 69; i++ { // headers and methods
		switch i % 3 {
		case 0:
			add(Match{Methods: []string{"DELETE", "PUT"}, Paths: []PathMatch{{Prefix: "/"}}})
		case 1:
			add(Match{Headers: []HeaderMatch{{Name: fmt.Sprintf("X-Evil-%d", i), Op: "present"}}})
		default:
			add(Match{Methods: []string{"GET"}, Headers: []HeaderMatch{
				{Name: "X-Api-Key", Op: "equals", Value: fmt.Sprintf("secret-%d", i)},
				{Name: "Referer", Op: "contains", Value: fmt.Sprintf("spam%d.example", i)},
			}})
		}
	}
	headerRegexes := []HeaderMatch{
		{Name: "Referer", Op: "regex", Value: `(?i)(casino|poker|viagra)`},
		{Name: "Referer", Op: "regex", Value: `^https?://[^/]*\.(ru|cn)/`},
		{Name: "Accept-Language", Op: "regex", Value: `^(zh|ru|vi)-`},
		{Name: "Accept-Language", Op: "regex", Value: `(?i)\b(xx|yy)\b`},
		{Name: "Referer", Op: "regex", Value: `(?i)(\?|&)q=.*(porn|pills)`},
		{Name: "Accept", Op: "regex", Value: `^application/(json|xml)`},
	}
	for _, h := range headerRegexes {
		add(Match{Headers: []HeaderMatch{h}})
	}
	for i := 0; i < 50; i++ { // hosts
		if i%2 == 0 {
			add(Match{Hosts: []string{fmt.Sprintf("evil-%d.example", i)}})
		} else {
			add(Match{Hosts: []string{fmt.Sprintf("*.evil-%d.example", i)}})
		}
	}
	for i := 0; i < 10; i++ { // except: half match and are suppressed, half fail outright
		r := enforce(fmt.Sprintf("bench-%d", len(rs)), Match{Paths: []PathMatch{{Prefix: "/products"}}})
		if i%2 == 1 {
			r.Match = Match{Paths: []PathMatch{{Prefix: fmt.Sprintf("/nowhere-%d", i)}}}
		}
		r.Except = &Match{IPs: []string{"198.51.100.0/24"}, UserAgents: []PathMatch{{Glob: "*Chrome*"}}}
		rs = append(rs, r)
	}
	queryTests := []HeaderMatch{
		{Name: "page", Op: "equals", Value: "3"},
		{Name: "utm_source", Op: "present"},
		{Name: "sort", Op: "regex", Value: `^(asc|desc)$`},
		{Name: "page", Op: "contains", Value: "x"},
		{Name: "debug", Op: "equals", Value: "1"},
		{Name: "sort", Op: "regex", Value: `(?i)union\s+select`},
		{Name: "id", Op: "present"},
		{Name: "page", Op: "regex", Value: `^[a-z]+$`},
		{Name: "cmd", Op: "present"},
		{Name: "sort", Op: "equals", Value: "rating"},
	}
	for _, q := range queryTests {
		add(Match{Query: []HeaderMatch{q}})
	}
	add(Match{ASNs: []uint{64496, 64497, 64498}})
	add(Match{ASNs: []uint{64499}, Paths: []PathMatch{{Prefix: "/"}}})
	add(Match{Datacenter: yes(true), Paths: []PathMatch{{Prefix: "/dc-only"}}})
	add(Match{ASNs: []uint{64500}, Methods: []string{"GET"}})
	add(Match{ASNs: []uint{64501}})
	return rs
}

// benchFacts is the request every benchmark evaluates; none of the rules
// above or below matches it.
func benchFacts(e *env) *Facts {
	r := httptest.NewRequest("GET", "/products/widgets?page=2&sort=price", nil)
	r.Host = "site.test"
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Referer", "https://search.example/?q=widgets")
	return e.facts(r, "198.51.100.7")
}

func BenchmarkEvaluate500Rules(b *testing.B) {
	rs := benchRules()
	if len(rs) != 500 {
		b.Fatalf("built %d rules, want 500", len(rs))
	}
	set, errs := Compile(rs)
	if errs != nil {
		b.Fatal(errs)
	}
	e := env{asn: 15169, asnOK: true}
	f := benchFacts(&e)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hit, logged := set.Evaluate(f)
		if hit != nil || logged != nil {
			b.Fatalf("unexpected match: %+v %v", hit, logged)
		}
	}
	b.StopTimer()
	if e.calls.asn != b.N {
		b.Fatalf("ASN() called %d times in %d evaluations, want once each", e.calls.asn, b.N)
	}
}

func benchRegexRules(b *testing.B, uaRegex func(i int) string, hdrRegex func(i int) HeaderMatch) {
	rs := make([]Rule, 0, 500)
	for i := 0; i < 500; i++ {
		var m Match
		if i%2 == 0 {
			m.UserAgents = []PathMatch{{Regex: uaRegex(i)}}
		} else {
			m.Headers = []HeaderMatch{hdrRegex(i)}
		}
		rs = append(rs, enforce(fmt.Sprintf("re-%d", i), m))
	}
	set, errs := Compile(rs)
	if errs != nil {
		b.Fatal(errs)
	}
	var e env
	f := benchFacts(&e)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if hit, logged := set.Evaluate(f); hit != nil || logged != nil {
			b.Fatalf("unexpected match: %+v %v", hit, logged)
		}
	}
}

// BenchmarkEvaluateRegexHeavy: 500 rules that are all unanchored regex tests
// on the User-Agent and headers, each containing a literal word as real
// patterns do. There is no budget; the number divided by 500 is the per-regex
// cost quoted on Set.Evaluate.
func BenchmarkEvaluateRegexHeavy(b *testing.B) {
	uaRegexes := []string{
		`(?i)python-requests|scrapy`, `(?i)(curl|wget|libwww)/[0-9]`, `(?i)headless(chrome)?`,
		`(?i)\b(spider|crawler)\b`, `(?i)go-http-client/[0-9.]+`, `(?i)(ahrefs|semrush|mj12)bot`,
	}
	headerRegexes := []HeaderMatch{
		{Name: "Referer", Op: "regex", Value: `(?i)(casino|poker|viagra)`},
		{Name: "Referer", Op: "regex", Value: `https?://[^/]*\.(ru|cn)/`},
		{Name: "Accept-Language", Op: "regex", Value: `(zh|ru|vi)-[A-Z]{2}`},
		{Name: "Accept-Language", Op: "regex", Value: `(?i)\b(xx|yy)\b`},
		{Name: "Accept", Op: "regex", Value: `application/(json|rss)`},
	}
	benchRegexRules(b,
		func(i int) string { return uaRegexes[i/2%len(uaRegexes)] + fmt.Sprintf("|zz%d", i) },
		func(i int) HeaderMatch {
			h := headerRegexes[i/2%len(headerRegexes)]
			h.Value += fmt.Sprintf("|zz%d", i)
			return h
		})
}

// BenchmarkEvaluateRegexHeavyNoLiteral is the true worst case: 500 regex
// rules with no literal for the prefilter to use, so every one runs the
// regexp engine over the whole value.
func BenchmarkEvaluateRegexHeavyNoLiteral(b *testing.B) {
	benchRegexRules(b,
		func(i int) string { return fmt.Sprintf(`[a-z]+/[0-9]+\.[0-9]+[a-z]{%d}`, 1+i%5) },
		func(i int) HeaderMatch {
			names := []string{"Referer", "Accept-Language", "Accept"}
			return HeaderMatch{Name: names[i/2%3], Op: "regex", Value: fmt.Sprintf(`[0-9]{%d}[A-Z]+[0-9]`, 6+i%5)}
		})
}

func TestPrefilterNeverChangesTheAnswer(t *testing.T) {
	inputs := []string{
		"", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0", "python-requests/2.31", "PYTHON-REQUESTS/2.31",
		"Scrapy/2.11 (+https://scrapy.org)", "curl/8.5.0", "CURL/8.5", "Wget/1.21", "libwww-perl/6.0",
		"xxspiderxx", "a spider b", "Googlebot/2.1", "AhrefsBot/7.0", "go-http-client/1.1", "Go-http-client/2.0",
		"\u212Aurl/1", "\u017Fcrapy", "caf\u00e9 SCRAPY", "\xff\xfescrapy", "headlesschrome", "HeadlessChrome/1",
		"/wp-admin/x.php", "/a/b/c", "ab", "a", "casino", "CASINO", "foo.example.com",
	}
	patterns := []string{
		`python-requests|scrapy`, `(?i)python-requests|scrapy`, `(?i)(curl|wget|libwww)/[0-9]`,
		`(?i)headless(chrome)?`, `(?i)\b(spider|crawler)\b`, `(?i)(ahrefs|semrush|mj12)bot`,
		`^/wp-(admin|login)\.php$`, `wp-admin.*\.php`, `(?i)k`, `(?i)kurl`, `(?i)scrapy`, `(?i)[a-z]+scrapy`,
		`(abc)+d`, `x{2,}yz`, `(?:foo|ba)r?`, `(?i)caf\x{e9}`, `\x{FFFD}ab`, `[0-9]+`, `.*`, `a|b`, `(?i)ca(sino|sh)`,
		`(?s)^/a.c$`, `(?i)foo\.example\.COM`,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		pre := newPrefilter(re)
		for _, in := range inputs {
			if pre != nil && !pre.allows(in) && re.MatchString(in) {
				t.Errorf("pattern %q input %q: prefilter rejected a string the regexp matches", p, in)
			}
		}
	}
}

func TestPrefilterUsedWhenALiteralIsRequired(t *testing.T) {
	tests := []struct {
		pattern string
		want    bool
	}{
		{`python-requests|scrapy`, true},
		{`(?i)(curl|wget)/[0-9]`, true},
		{`^/old/(admin|login)\.php$`, true},
		{`[a-z]+[0-9]+`, false},
		{`a|[0-9]`, false},
		{`.*`, false},
		{`x`, false}, // too short to be worth it
	}
	for _, tt := range tests {
		if got := newPrefilter(regexp.MustCompile(tt.pattern)) != nil; got != tt.want {
			t.Errorf("pattern %q: prefilter present = %v, want %v", tt.pattern, got, tt.want)
		}
	}
}
