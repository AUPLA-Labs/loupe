package rules

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

const fullRulesYAML = `
rules:
  - id: block-scrapers
    name: Block scrapers
    enabled: true
    mode: enforce
    action: block
    note: seen hammering /api
    expires: 2027-01-02T03:04:05Z
    match:
      ips: [203.0.113.0/24, 2001:db8::1]
      asns: [64496, 64497]
      hosts: [example.com, "*.example.com"]
      methods: [get, post]
      paths:
        - prefix: /api/
        - exact: /login
        - glob: /static/*.js
        - regex: ^/v[0-9]+/
      headers:
        - {name: x-forwarded-for, op: contains, value: "10."}
        - {name: x-debug, op: absent}
      query:
        - {name: utm, op: present}
      user_agents:
        - glob: "*curl/*"
      countries: [us, de]
      datacenter: true
      bad_ip_at_least: 50
      bots: [googlebot]
      cleared: false
    except:
      ips: [203.0.113.7]
  - id: ask-nicely
    action: challenge
    tier: single_click
    match:
      paths: [{prefix: /checkout}]
`

func TestParseRulesYAML(t *testing.T) {
	rs, err := Parse([]byte(fullRulesYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rs) != 2 {
		t.Fatalf("got %d rules, want 2", len(rs))
	}
	r := rs[0]
	if r.ID != "block-scrapers" || r.Name != "Block scrapers" || r.Mode != ModeEnforce || r.Action != ActionBlock || r.Note == "" {
		t.Errorf("scalar fields not decoded: %+v", r)
	}
	if r.Enabled == nil || !*r.Enabled {
		t.Errorf("enabled not decoded: %v", r.Enabled)
	}
	if r.Expires == nil || r.Expires.Year() != 2027 {
		t.Errorf("expires not decoded: %v", r.Expires)
	}
	m := r.Match
	if len(m.IPs) != 2 || len(m.ASNs) != 2 || len(m.Hosts) != 2 || len(m.Methods) != 2 ||
		len(m.Paths) != 4 || len(m.Headers) != 2 || len(m.Query) != 1 || len(m.UserAgents) != 1 ||
		len(m.Countries) != 2 || m.Datacenter == nil || !*m.Datacenter || m.BadIPAtLeast != 50 ||
		len(m.Bots) != 1 || m.Cleared == nil || *m.Cleared {
		t.Errorf("match not decoded: %+v", m)
	}
	if m.Paths[3].Regex != "^/v[0-9]+/" || m.Headers[0].Op != "contains" {
		t.Errorf("nested matchers not decoded: %+v", m)
	}
	if r.Except == nil || len(r.Except.IPs) != 1 {
		t.Errorf("except not decoded: %+v", r.Except)
	}
	if rs[1].Tier != "single_click" {
		t.Errorf("tier = %q", rs[1].Tier)
	}
	if _, err := Compile(rs); err != nil {
		t.Errorf("the full example should compile: %v", err)
	}

	if _, err := Parse([]byte("rules:\n  - id: a\n    acton: block\n")); err == nil {
		t.Error("an unknown key (acton) must be an error")
	}
	if _, err := Parse([]byte("rules:\n  - id: a\n    match:\n      pths: []\n")); err == nil {
		t.Error("an unknown key inside match must be an error")
	}
	if rs, err := Parse(nil); err != nil || len(rs) != 0 {
		t.Errorf("an empty file is an empty rule set, got %v, %v", rs, err)
	}
	if rs, err := Parse([]byte("# only a comment\n")); err != nil || len(rs) != 0 {
		t.Errorf("a comment-only file is an empty rule set, got %v, %v", rs, err)
	}
}

// okRule is a valid rule; the table below breaks one thing at a time.
func okRule() Rule {
	return Rule{
		ID:     "r1",
		Action: ActionBlock,
		Match:  Match{Paths: []PathMatch{{Prefix: "/x"}}},
	}
}

func TestCompileReportsRuleID(t *testing.T) {
	long := strings.Repeat("a", 1025)
	tests := []struct {
		name      string
		rules     func() []Rule
		wantIndex int
		wantID    string
		wantField string
		wantMsg   string
	}{
		{"missing id", func() []Rule { r := okRule(); r.ID = ""; return []Rule{r} }, 0, "", "id", "id is required"},
		{"uppercase id", func() []Rule { r := okRule(); r.ID = "Bad"; return []Rule{r} }, 0, "Bad", "id", "invalid id"},
		{"id starting with dash", func() []Rule { r := okRule(); r.ID = "-x"; return []Rule{r} }, 0, "-x", "id", "invalid id"},
		{"id too long", func() []Rule { r := okRule(); r.ID = strings.Repeat("a", 65); return []Rule{r} }, 0, strings.Repeat("a", 65), "id", "invalid id"},
		{"duplicate id", func() []Rule { a, b := okRule(), okRule(); return []Rule{a, b} }, 1, "r1", "id", "duplicate id"},
		{"bad mode", func() []Rule { r := okRule(); r.Mode = "audit"; return []Rule{r} }, 0, "r1", "mode", "unknown mode"},
		{"missing action", func() []Rule { r := okRule(); r.Action = ""; return []Rule{r} }, 0, "r1", "action", "action is required"},
		{"bad action", func() []Rule { r := okRule(); r.Action = "drop"; return []Rule{r} }, 0, "r1", "action", "unknown action"},
		{"challenge without tier", func() []Rule { r := okRule(); r.Action = ActionChallenge; return []Rule{r} }, 0, "r1", "tier", "tier is required"},
		{"unknown tier", func() []Rule { r := okRule(); r.Action = ActionChallenge; r.Tier = "singleclick"; return []Rule{r} }, 0, "r1", "tier", `unknown tier "singleclick"`},
		{"pulse is not a rule tier", func() []Rule { r := okRule(); r.Action = ActionChallenge; r.Tier = "pulse"; return []Rule{r} }, 0, "r1", "tier", `unknown tier "pulse"`},
		{"tier on block", func() []Rule { r := okRule(); r.Tier = "prism"; return []Rule{r} }, 0, "r1", "tier", "tier only applies to challenge"},
		{"empty match", func() []Rule { r := okRule(); r.Match = Match{}; return []Rule{r} }, 0, "r1", "match", "match is empty"},
		{"empty except", func() []Rule { r := okRule(); r.Except = &Match{}; return []Rule{r} }, 0, "r1", "except", "except is empty"},
		{"bad ip", func() []Rule { r := okRule(); r.Match.IPs = []string{"10.0.0.1", "10.0.0.0/33"}; return []Rule{r} }, 0, "r1", "match.ips[1]", `invalid address or CIDR "10.0.0.0/33"`},
		{"bad ip in except", func() []Rule { r := okRule(); r.Except = &Match{IPs: []string{"nope"}}; return []Rule{r} }, 0, "r1", "except.ips[0]", `invalid address or CIDR "nope"`},
		{"empty host", func() []Rule { r := okRule(); r.Match.Hosts = []string{"a.com", ""}; return []Rule{r} }, 0, "r1", "match.hosts[1]", `invalid host ""`},
		{"star without dot", func() []Rule { r := okRule(); r.Match.Hosts = []string{"*example.com"}; return []Rule{r} }, 0, "r1", "match.hosts[0]", `invalid host "*example.com"`},
		{"trailing star host", func() []Rule { r := okRule(); r.Match.Hosts = []string{"www.*"}; return []Rule{r} }, 0, "r1", "match.hosts[0]", `invalid host "www.*"`},
		{"two wildcards in host", func() []Rule { r := okRule(); r.Match.Hosts = []string{"*.*.example.com"}; return []Rule{r} }, 0, "r1", "match.hosts[0]", `invalid host "*.*.example.com"`},
		{"wildcard with no label", func() []Rule { r := okRule(); r.Match.Hosts = []string{"*."}; return []Rule{r} }, 0, "r1", "match.hosts[0]", `invalid host "*."`},
		{"middle star host in except", func() []Rule { r := okRule(); r.Except = &Match{Hosts: []string{"a.*.com"}}; return []Rule{r} }, 0, "r1", "except.hosts[0]", `invalid host "a.*.com"`},
		{"path with no field", func() []Rule { r := okRule(); r.Match.Paths = append(r.Match.Paths, PathMatch{}); return []Rule{r} }, 0, "r1", "match.paths[1]", "set exactly one of prefix, exact, glob, regex"},
		{"path with two fields", func() []Rule {
			r := okRule()
			r.Match.Paths = []PathMatch{{Prefix: "/a", Exact: "/a"}}
			return []Rule{r}
		}, 0, "r1", "match.paths[0]", "set exactly one of prefix, exact, glob, regex"},
		{"bad path regex", func() []Rule {
			r := okRule()
			r.Match.Paths = []PathMatch{{Prefix: "/ok"}, {Regex: "(unclosed"}}
			return []Rule{r}
		}, 0, "r1", "match.paths[1].regex", "invalid regex"},
		{"path regex with lookahead (not RE2)", func() []Rule {
			r := okRule()
			r.Match.Paths = []PathMatch{{Regex: "^/(?!admin)"}}
			return []Rule{r}
		}, 0, "r1", "match.paths[0].regex", "invalid regex"},
		{"path regex too long", func() []Rule {
			r := okRule()
			r.Match.Paths = []PathMatch{{Regex: long}}
			return []Rule{r}
		}, 0, "r1", "match.paths[0].regex", "at most 1024"},
		{"bad ua regex", func() []Rule {
			r := okRule()
			r.Match.UserAgents = []PathMatch{{Regex: "["}}
			return []Rule{r}
		}, 0, "r1", "match.user_agents[0].regex", "invalid regex"},
		{"unknown header op", func() []Rule {
			r := okRule()
			r.Match.Headers = []HeaderMatch{{Name: "X-A", Op: "startswith", Value: "a"}}
			return []Rule{r}
		}, 0, "r1", "match.headers[0].op", `unknown op "startswith"`},
		{"header missing name", func() []Rule {
			r := okRule()
			r.Match.Headers = []HeaderMatch{{Op: "present"}}
			return []Rule{r}
		}, 0, "r1", "match.headers[0].name", "name is required"},
		{"equals without value", func() []Rule {
			r := okRule()
			r.Match.Headers = []HeaderMatch{{Name: "X-A", Op: "equals"}}
			return []Rule{r}
		}, 0, "r1", "match.headers[0].value", "value is required"},
		{"present with value", func() []Rule {
			r := okRule()
			r.Match.Headers = []HeaderMatch{{Name: "X-A", Op: "present", Value: "x"}}
			return []Rule{r}
		}, 0, "r1", "match.headers[0].value", "value not allowed"},
		{"absent with value", func() []Rule {
			r := okRule()
			r.Match.Query = []HeaderMatch{{Name: "q", Op: "absent", Value: "x"}}
			return []Rule{r}
		}, 0, "r1", "match.query[0].value", "value not allowed"},
		{"bad header regex", func() []Rule {
			r := okRule()
			r.Match.Headers = []HeaderMatch{{Name: "X-A", Op: "regex", Value: "(x"}}
			return []Rule{r}
		}, 0, "r1", "match.headers[0].value", "invalid regex"},
		{"bad query regex in except", func() []Rule {
			r := okRule()
			r.Except = &Match{Query: []HeaderMatch{{Name: "q", Op: "regex", Value: "(x"}}}
			return []Rule{r}
		}, 0, "r1", "except.query[0].value", "invalid regex"},
		{"country of three letters", func() []Rule { r := okRule(); r.Match.Countries = []string{"US", "USA"}; return []Rule{r} }, 0, "r1", "match.countries[1]", `invalid country "USA"`},
		{"country with digit", func() []Rule { r := okRule(); r.Match.Countries = []string{"U1"}; return []Rule{r} }, 0, "r1", "match.countries[0]", `invalid country "U1"`},
		{"registered country", func() []Rule { r := okRule(); r.Match.RegisteredCountries = []string{"DEU"}; return []Rule{r} }, 0, "r1", "match.registered_countries[0]", `invalid country "DEU"`},
		{"network type", func() []Rule { r := okRule(); r.Match.NetworkTypes = []string{"isp", "cloud"}; return []Rule{r} }, 0, "r1", "match.network_types[1]", `unknown value "cloud"`},
		{"network role", func() []Rule { r := okRule(); r.Match.NetworkRoles = []string{"tier2"}; return []Rule{r} }, 0, "r1", "match.network_roles[0]", `unknown value "tier2"`},
		{"class", func() []Rule { r := okRule(); r.Match.Classes = []string{"VPN"}; return []Rule{r} }, 0, "r1", "match.classes[0]", `unknown value "VPN"`},
		{"list id", func() []Rule { r := okRule(); r.Match.Lists = []string{"Mullvad VPN"}; return []Rule{r} }, 0, "r1", "match.lists[0]", `invalid list id`},
		{"negative bad ip score", func() []Rule { r := okRule(); r.Match.BadIPAtLeast = -1; return []Rule{r} }, 0, "r1", "match.bad_ip_at_least", "must be 0 or more"},
		{"empty bot id", func() []Rule { r := okRule(); r.Match.Bots = []string{"googlebot", ""}; return []Rule{r} }, 0, "r1", "match.bots[1]", "empty bot id"},
		{"empty bot id in except", func() []Rule { r := okRule(); r.Except = &Match{Bots: []string{""}}; return []Rule{r} }, 0, "r1", "except.bots[0]", "empty bot id"},
		{"empty method", func() []Rule { r := okRule(); r.Match.Methods = []string{"GET", " "}; return []Rule{r} }, 0, "r1", "match.methods[1]", "empty method"},
		{"host with port", func() []Rule { r := okRule(); r.Match.Hosts = []string{"example.com:443"}; return []Rule{r} }, 0, "r1", "match.hosts[0]", `invalid host "example.com:443" (no port: hosts match without one)`},
		{"wildcard host with port", func() []Rule { r := okRule(); r.Match.Hosts = []string{"*.example.com:443"}; return []Rule{r} }, 0, "r1", "match.hosts[0]", "no port"},
		{"bracketed ipv6 host with port", func() []Rule { r := okRule(); r.Match.Hosts = []string{"[::1]:8080"}; return []Rule{r} }, 0, "r1", "match.hosts[0]", "no port"},
		{"host that is only a dot", func() []Rule { r := okRule(); r.Match.Hosts = []string{"."}; return []Rule{r} }, 0, "r1", "match.hosts[0]", "invalid host"},
		{"wildcard with only a dot", func() []Rule { r := okRule(); r.Match.Hosts = []string{"*.."}; return []Rule{r} }, 0, "r1", "match.hosts[0]", "invalid host"},
		{"cidr with host bits", func() []Rule { r := okRule(); r.Match.IPs = []string{"203.0.113.77/16"}; return []Rule{r} }, 0, "r1", "match.ips[0]", `"203.0.113.77/16" has host bits set; did you mean 203.0.113.77/32?`},
		{"cidr with host bits suggests the network", func() []Rule { r := okRule(); r.Match.IPs = []string{"10.1.2.0/15"}; return []Rule{r} }, 0, "r1", "match.ips[0]", "did you mean 10.0.0.0/15?"},
		{"ipv6 cidr with host bits", func() []Rule { r := okRule(); r.Match.IPs = []string{"2001:db8::5/32"}; return []Rule{r} }, 0, "r1", "match.ips[0]", "did you mean 2001:db8::5/128?"},
		{"cidr with host bits in except", func() []Rule { r := okRule(); r.Except = &Match{IPs: []string{"192.0.2.1/24"}}; return []Rule{r} }, 0, "r1", "except.ips[0]", "has host bits set"},
		{"asn zero", func() []Rule { r := okRule(); r.Match.ASNs = []uint{64496, 0}; return []Rule{r} }, 0, "r1", "match.asns[1]", "ASN 0 is not a network"},
		{"second rule is the one reported", func() []Rule {
			b := okRule()
			b.ID = "second"
			b.Action = "drop"
			return []Rule{okRule(), b}
		}, 1, "second", "action", "unknown action"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			set, errs := Compile(tc.rules())
			if set != nil {
				t.Error("Compile must return a nil set when any rule is invalid")
			}
			if len(errs) == 0 {
				t.Fatal("expected an error, got none")
			}
			var found bool
			for _, err := range errs {
				var re *RuleError
				if !errors.As(err, &re) {
					t.Fatalf("error %v is not a *RuleError", err)
				}
				if re.Index == tc.wantIndex && re.ID == tc.wantID && re.Field == tc.wantField && strings.Contains(re.Msg, tc.wantMsg) {
					found = true
				}
			}
			if !found {
				t.Errorf("no RuleError with index %d, id %q, field %q, msg containing %q in %v",
					tc.wantIndex, tc.wantID, tc.wantField, tc.wantMsg, errs)
			}
		})
	}
}

func TestRuleErrorText(t *testing.T) {
	tests := []struct {
		err  RuleError
		want string
	}{
		{RuleError{Index: 2, ID: "r1", Field: "match.paths[1].regex", Msg: "bad"}, `rule "r1": match.paths[1].regex: bad`},
		{RuleError{Index: 2, Field: "id", Msg: "id is required"}, `rule #3: id: id is required`},
	}
	for _, tc := range tests {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("Error() = %q, want %q", got, tc.want)
		}
	}
}

func TestCompileReportsEveryError(t *testing.T) {
	a, b := okRule(), okRule()
	a.Action = "drop"
	b.ID = "r2"
	b.Match.IPs = []string{"nope"}
	b.Mode = "audit"
	if set, errs := Compile([]Rule{a, b}); set != nil || len(errs) != 3 {
		t.Errorf("want a nil set and 3 errors, got set=%v errs=%v", set, errs)
	}
}

func TestCompileDefaults(t *testing.T) {
	set, errs := Compile([]Rule{okRule()})
	if len(errs) != 0 {
		t.Fatalf("Compile: %v", errs)
	}
	c := set.rules[0]
	if !c.enabled || !okRule().IsEnabled() {
		t.Error("a rule with no enabled key must be enabled")
	}
	if c.mode != ModeLog {
		t.Errorf("a rule with no mode must be in log mode, got %q", c.mode)
	}
	off := false
	r := okRule()
	r.Enabled = &off
	set, errs = Compile([]Rule{r})
	if len(errs) != 0 || set.rules[0].enabled || r.IsEnabled() {
		t.Errorf("enabled: false must compile as disabled (errs %v)", errs)
	}
}

func TestCompileNormalizesMatchers(t *testing.T) {
	yes := true
	r := Rule{
		ID: "n", Action: ActionChallenge, Tier: "lumen_auto",
		Match: Match{
			IPs:        []string{"192.0.2.1", "2001:db8::/32", "2001:db8::5"},
			ASNs:       []uint{64496},
			Hosts:      []string{"Example.COM", "*.Cdn.Example.com"},
			Methods:    []string{"get", "Post"},
			Paths:      []PathMatch{{Glob: "/a.b/*/c?"}, {Prefix: "/p"}, {Regex: "^/r"}},
			Headers:    []HeaderMatch{{Name: "x-forwarded-for", Op: "present"}},
			Query:      []HeaderMatch{{Name: "utm_Source", Op: "equals", Value: "x"}},
			Countries:  []string{"de"},
			Datacenter: &yes,
		},
	}
	set, errs := Compile([]Rule{r})
	if len(errs) != 0 {
		t.Fatalf("Compile: %v", errs)
	}
	m := set.rules[0].match
	if set.rules[0].tier != tier.LumenAuto {
		t.Errorf("tier = %v, want lumen_auto", set.rules[0].tier)
	}
	if len(m.ips) != 3 || m.ips[0].String() != "192.0.2.1/32" || m.ips[2].String() != "2001:db8::5/128" {
		t.Errorf("ips = %v", m.ips)
	}
	if _, ok := m.asns[64496]; !ok {
		t.Error("asn 64496 missing")
	}
	if _, ok := m.hostExact["example.com"]; !ok || len(m.hostSuffix) != 1 || m.hostSuffix[0] != ".cdn.example.com" {
		t.Errorf("hosts = %v %v", m.hostExact, m.hostSuffix)
	}
	_, get := m.methods["GET"]
	_, post := m.methods["POST"]
	if !get || !post || len(m.methods) != 2 {
		t.Errorf("methods = %v, want GET and POST", m.methods)
	}
	if p := m.paths[0]; !p.match("/a.b/zz/cx") || p.match("/aXb/zz/cx") || p.match("/a.b/zz/c") || p.match("x/a.b/zz/cx") {
		t.Error("glob did not compile to an anchored pattern with * and ? and everything else quoted")
	}
	if !m.paths[1].match("/pq") || m.paths[1].match("/q") || !m.paths[2].match("/rx") {
		t.Error("prefix or regex matcher wrong")
	}
	if m.headers[0].name != "X-Forwarded-For" {
		t.Errorf("header name = %q, want canonical", m.headers[0].name)
	}
	if m.query[0].name != "utm_Source" {
		t.Errorf("query name = %q, want as written", m.query[0].name)
	}
	if _, ok := m.countries["DE"]; !ok {
		t.Error("country not upper-cased")
	}
	if m.datacenter == nil || !*m.datacenter {
		t.Error("datacenter lost")
	}
}

func TestCompileAcceptsValidRules(t *testing.T) {
	yes := true
	rs := []Rule{
		{ID: "allow-google", Action: ActionAllow, Mode: ModeEnforce, Match: Match{Bots: []string{"googlebot"}}},
		{ID: "block-net", Action: ActionBlock, Mode: ModeEnforce, Match: Match{IPs: []string{"198.51.100.0/24"}}},
		{ID: "challenge-admin", Action: ActionChallenge, Tier: "prism", Match: Match{Paths: []PathMatch{{Prefix: "/admin"}}}},
		{ID: "log-curl", Action: ActionLog, Match: Match{UserAgents: []PathMatch{{Glob: "curl/*"}}}},
		{
			ID: "block-dc-except-office", Action: ActionBlock,
			Match:  Match{Datacenter: &yes, Methods: []string{"POST"}},
			Except: &Match{IPs: []string{"203.0.113.9"}, ASNs: []uint{64500}},
		},
	}
	set, errs := Compile(rs)
	if len(errs) != 0 || set == nil {
		t.Fatalf("Compile: %v", errs)
	}
	if set.Len() != 5 {
		t.Errorf("Len() = %d, want 5", set.Len())
	}
	if set.rules[4].except == nil {
		t.Error("except not compiled")
	}
	if (*Set)(nil).Len() != 0 {
		t.Error("a nil set has no rules")
	}
}

func TestGlobCompilesToFastKinds(t *testing.T) {
	tests := []struct {
		glob string
		want textKind
	}{
		{"/static/app.js", kindExact},
		{"/static/*", kindPrefix},
		{"*", kindPrefix},
		{"*.js", kindSuffix},
		{"*scraper*", kindContains},
		{"**", kindContains},
		{"a**b", kindSegments},
		{"/a/*/b", kindSegments},
		{"a*b*c", kindSegments},
		{"*a*b", kindSegments},
		{"a*b*", kindSegments},
		{"/a/?", kindRegex},
		{"*a?*", kindRegex},
	}
	for _, tc := range tests {
		tm, msg := compileGlob(tc.glob)
		if msg != "" || tm.kind != tc.want {
			t.Errorf("glob %q: kind %d (err %q), want %d", tc.glob, tm.kind, msg, tc.want)
		}
	}
}

// TestGlobSemantics holds the fast matchers to the anchored-regexp meaning of
// a glob, so the two can't drift apart.
func TestGlobSemantics(t *testing.T) {
	globs := []string{
		"", "a", "*", "**", "***", "a*", "*a", "*a*", "a*b", "a**b", "a*b*c", "*a*b*", "a*a", "*a*a*",
		"/api/*", "/a/*/b", "*/", "*/*", "/static/*.js", "*.php", "*curl*", "curl/*", "ab*ba", "a?b",
		"?", "a?", "*?", "/x/?*", "é*", "a*é", "a.b*", "(x)*", "*[0-9]",
	}
	inputs := []string{
		"", "a", "b", "aa", "ab", "ba", "aba", "abba", "ab ba", "a/b", "/a/b", "/a/x/b", "/a//b", "/a/b/c",
		"/", "//", "x/", "/api/", "/api/v1/users", "/api", "/static/app.js", "/static/a/b.js", "/static/.js",
		"x.php", ".php", "x.php.bak", "curl/8.0", "libcurl", "mycurl/1", "acb", "aXb", "a\nb", "a\nb\nc",
		"é", "éa", "aé", "aéb", "a.b", "a.bc", "axb", "(x)", "(x)y", "7", "x7", "x7y", "aaa", "aabaa",
	}
	for _, g := range globs {
		tm, msg := compileGlob(g)
		if msg != "" {
			t.Fatalf("glob %q: %s", g, msg)
		}
		ref := regexp.MustCompile(globRegex(g))
		for _, in := range inputs {
			if got, want := tm.match(in), ref.MatchString(in); got != want {
				t.Errorf("glob %q on %q: fast matcher = %v, anchored regexp = %v", g, in, got, want)
			}
		}
	}
}

func BenchmarkGlob500(b *testing.B) {
	rs := make([]Rule, 500)
	for i := range rs {
		rs[i] = Rule{
			ID:     fmt.Sprintf("ua-%d", i),
			Action: ActionBlock,
			Match:  Match{UserAgents: []PathMatch{{Glob: fmt.Sprintf("*scraper%d*", i)}}},
		}
	}
	set, errs := Compile(rs)
	if errs != nil {
		b.Fatal(errs)
	}
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, c := range set.rules {
			for _, m := range c.match.userAgents {
				if m.match(ua) {
					b.Fatal("unexpected match")
				}
			}
		}
	}
}

func TestParseRejectsSecondDocument(t *testing.T) {
	two := "rules:\n  - id: a\n    action: block\n---\nrules:\n  - id: b\n    action: block\n"
	rs, err := Parse([]byte(two))
	if err == nil || err.Error() != "rules.yaml must hold one YAML document" {
		t.Fatalf("Parse of two documents = %v, %v; want the one-document error", rs, err)
	}
	if rs != nil {
		t.Errorf("rules = %v, want nil on error", rs)
	}
	// A trailing separator with nothing after it is still an empty second
	// document, which is rejected too: the file is ambiguous.
	if _, err := Parse([]byte("rules: []\n---\n")); err == nil {
		t.Error("a trailing --- must be rejected")
	}
	if rs, err := Parse([]byte("---\nrules:\n  - id: a\n    action: block\n")); err != nil || len(rs) != 1 {
		t.Errorf("a leading --- is one document, got %v, %v", rs, err)
	}
}

func TestCompileNormalisesHosts(t *testing.T) {
	// The request side drops the port and a trailing dot, so a rule written
	// with a trailing dot must still match.
	s := mustCompile(t, enforce("r1", Match{Hosts: []string{"Example.com.", "*.Other.test."}}))
	for host, want := range map[string]bool{
		"example.com":      true,
		"example.com.:443": true,
		"a.other.test":     true,
		"other.test":       false,
		"example.org":      false,
	} {
		p := probe{host: host}
		hit, _, _ := p.run(t, s)
		if (hit != nil) != want {
			t.Errorf("host %q: hit = %v, want match %v", host, hit, want)
		}
	}
}

func TestCompileKeepsBracketedIPv6Host(t *testing.T) {
	s := mustCompile(t, enforce("r1", Match{Hosts: []string{"[::1]"}}))
	p := probe{host: "[::1]:8080"}
	if hit, _, _ := p.run(t, s); hit == nil {
		t.Error("a bracketed IPv6 literal host should still match")
	}
}

func TestCompileAcceptsMaskedCIDRsAndAddresses(t *testing.T) {
	mustCompile(t, enforce("r1", Match{IPs: []string{"203.0.113.0/24", "203.0.113.77", "2001:db8::/32", "2001:db8::5", "0.0.0.0/0", "::/0", "203.0.113.77/32"}}))
}
