package rules

import (
	"strings"
	"testing"
	"time"
)

// limitRule is an enforced rate limit on /login: n requests a minute.
func limitRule(id string, n int, by string) Rule {
	return Rule{ID: id, Mode: ModeEnforce, Action: ActionRateLimit,
		Limit: &Limit{Requests: n, Period: "1m", By: by},
		Match: Match{Paths: []PathMatch{{Exact: "/login"}}}}
}

func TestRateLimitRuleExceeded(t *testing.T) {
	s := mustCompile(t, limitRule("login", 2, ""), enforce("after", Match{Paths: []PathMatch{{Prefix: "/"}}}))
	p := probe{target: "/login"}
	for i := range 2 {
		// Within the budget the search goes on to the next rule.
		if hit, _, _ := p.run(t, s); hit == nil || hit.ID != "after" {
			t.Fatalf("request %d: hit %+v, want the rule after the limit", i+1, hit)
		}
	}
	hit, _, _ := p.run(t, s)
	if hit == nil || hit.ID != "login" || hit.Action != ActionRateLimit || hit.Then != ActionBlock || hit.RetryAfter <= 29*time.Second || hit.RetryAfter > 30*time.Second {
		t.Fatalf("3rd request: hit %+v, want login rate limit, block, retry in 30s", hit)
	}
	if hit, _, _ := (probe{target: "/login", ip: "198.51.100.8"}).run(t, s); hit == nil || hit.ID != "after" {
		t.Fatalf("another client was limited by the first one's count: %+v", hit)
	}
}

func TestRateLimitLogModeNeverLimits(t *testing.T) {
	r := limitRule("login", 1, "")
	r.Mode = ModeLog
	s := mustCompile(t, r)
	p := probe{target: "/login"}
	if hit, logged, _ := p.run(t, s); hit != nil || len(logged) != 0 {
		t.Fatalf("1st request: hit %+v logged %v, want neither", hit, logged)
	}
	hit, logged, _ := p.run(t, s)
	if hit != nil || len(logged) != 1 || logged[0] != "login" {
		t.Fatalf("2nd request: hit %+v logged %v, want only logged", hit, logged)
	}
}

func TestRateLimitKeyFallsBackWhenHeaderMissing(t *testing.T) {
	s := mustCompile(t, limitRule("api", 1, "header:x-api-key"))
	withKey := func(k string) probe { return probe{target: "/login", hdr: [][2]string{{"X-Api-Key", k}}} }
	if hit, _, _ := withKey("a").run(t, s); hit != nil {
		t.Fatal("first request with key a was limited")
	}
	if hit, _, _ := withKey("a").run(t, s); hit == nil {
		t.Fatal("second request with key a was not limited")
	}
	if hit, _, _ := withKey("b").run(t, s); hit != nil {
		t.Fatal("key b was limited by key a's count")
	}
	// Without the header the client is counted by address, and the same
	// address with no header can't start over.
	if hit, _, _ := (probe{target: "/login"}).run(t, s); hit != nil {
		t.Fatal("first request without a key was limited")
	}
	if hit, _, _ := (probe{target: "/login"}).run(t, s); hit == nil {
		t.Fatal("dropping the header escaped the limit")
	}
}

func TestRateLimitDryRunSpendsNothing(t *testing.T) {
	s := mustCompile(t, limitRule("login", 1, ""))
	p := probe{target: "/login"}
	for range 3 {
		e := p.env
		req := newProbeRequest(p)
		hit, _, counted := s.DryRun(e.facts(req, "198.51.100.7"))
		if hit != nil || len(counted) != 1 || counted[0] != "login" {
			t.Fatalf("dry run: hit %+v counted %v", hit, counted)
		}
	}
	if hit, _, _ := p.run(t, s); hit != nil {
		t.Fatal("dry runs used up the budget")
	}
}

func TestLimiterSurvivesUnrelatedRuleSave(t *testing.T) {
	m := NewManager(t.TempDir() + "/rules.yaml")
	save := func(rs ...Rule) {
		t.Helper()
		if err := m.Save(rs); err != nil {
			t.Fatal(err)
		}
	}
	p := probe{target: "/login"}
	save(limitRule("login", 1, ""))
	p.run(t, m.Set())
	save(limitRule("login", 1, ""), enforce("other", Match{Paths: []PathMatch{{Exact: "/x"}}}))
	if hit, _, _ := p.run(t, m.Set()); hit == nil {
		t.Fatal("saving an unrelated rule reset the limit's counters")
	}
	save(limitRule("login", 2, ""))
	if hit, _, _ := p.run(t, m.Set()); hit != nil {
		t.Fatal("a changed limit kept the old counters")
	}
}

func TestCompileChecksLimits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		r     Rule
		field string
	}{
		{"no limit", Rule{ID: "r", Action: ActionRateLimit, Match: Match{Methods: []string{"GET"}}}, "limit"},
		{"limit on block", Rule{ID: "r", Action: ActionBlock, Limit: &Limit{Requests: 1, Period: "1m"}, Match: Match{Methods: []string{"GET"}}}, "limit"},
		{"zero requests", func() Rule { r := limitRule("r", 0, ""); return r }(), "limit.requests"},
		{"bad period", func() Rule { r := limitRule("r", 1, ""); r.Limit.Period = "soon"; return r }(), "limit.period"},
		{"long period", func() Rule { r := limitRule("r", 1, ""); r.Limit.Period = "48h"; return r }(), "limit.period"},
		{"bad by", limitRule("r", 1, "asn"), "limit.by"},
		{"by without name", limitRule("r", 1, "header:"), "limit.by"},
		{"bad then", func() Rule { r := limitRule("r", 1, ""); r.Limit.Then = "allow"; return r }(), "limit.then"},
		{"challenge without tier", func() Rule { r := limitRule("r", 1, ""); r.Limit.Then = ActionChallenge; return r }(), "tier"},
		{"tier with block", func() Rule { r := limitRule("r", 1, ""); r.Tier = "prism"; return r }(), "tier"},
	} {
		_, errs := Compile([]Rule{tc.r})
		if len(errs) != 1 || errs[0].(*RuleError).Field != tc.field {
			t.Errorf("%s: errors %v, want one on %s", tc.name, errs, tc.field)
		}
	}
	r := limitRule("r", 1, "cookie:session")
	r.Limit.Then, r.Tier = ActionChallenge, "prism"
	if _, errs := Compile([]Rule{r}); errs != nil {
		t.Errorf("valid challenge limit: %v", errs)
	}
}

func TestLimitParsesFromYAML(t *testing.T) {
	rs, err := Parse([]byte("rules:\n  - id: login\n    action: rate_limit\n    limit: {requests: 5, period: 1m, by: \"header:X-Api-Key\", then: block}\n    match: {paths: [{exact: /login}]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l := rs[0].Limit; l == nil || l.Requests != 5 || l.Period != "1m" || !strings.HasPrefix(l.By, "header:") || l.Then != ActionBlock {
		t.Fatalf("parsed limit %+v", rs[0].Limit)
	}
}
