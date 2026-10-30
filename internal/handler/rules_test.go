package handler

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/admin"
	"github.com/AUPLA-Labs/loupe/internal/asn"
	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/rules"
)

// rulesFixture is a real Handler (built with New) in front of a counting
// backend, with the given rules.yaml.
type rulesFixture struct {
	h       *Handler
	store   *admin.Store
	backend *atomic.Int64
}

func newRulesFixture(t *testing.T, rulesYAML string) *rulesFixture {
	t.Helper()
	return newRulesFixtureWith(t, rulesYAML, "", nil)
}

// newRulesFixtureWith also appends extraYAML to config.yaml and lets seen
// look at each request the backend receives.
func newRulesFixtureWith(t *testing.T, rulesYAML, extraYAML string, seen func(*http.Request)) *rulesFixture {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if seen != nil {
			seen(r)
		}
		w.Write([]byte("content")) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	if rulesYAML != "" {
		if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.LoadBytes([]byte(fmt.Sprintf(`
backend: %s
hmac_secret: test-secret
asn:
  db_path: %s
  token_file: %s
bots:
  policy_file: %s
  ranges_dir: %s
rules:
  file: %s
%s`, srv.URL, filepath.Join(dir, "asn.aupldb"), filepath.Join(dir, "token"),
		filepath.Join(dir, "bots.yaml"), filepath.Join(dir, "ranges"), rulesPath, extraYAML)))
	if err != nil {
		t.Fatal(err)
	}
	store, err := admin.NewStore(100, "")
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(cfg, store, testReputationStore(t))
	if err != nil {
		t.Fatalf("New must succeed whatever rules.yaml holds: %v", err)
	}
	t.Cleanup(h.Close)
	return &rulesFixture{h: h, store: store, backend: &hits}
}

func (f *rulesFixture) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

// events returns the stored events with the given action and reason.
func (f *rulesFixture) events(action, reason string) []admin.Event {
	var out []admin.Event
	for _, e := range f.store.Recent(0, action) {
		if e.Reason == reason {
			out = append(out, e)
		}
	}
	return out
}

// fromIP is a Chrome navigation arriving from addr.
func fromIP(addr string) *http.Request {
	r := chromeNav()
	r.RemoteAddr = addr + ":1234"
	return r
}

func TestRuleAllowSkipsChallenge(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: let-partner-in
    mode: enforce
    action: allow
    match: {ips: ["1.2.3.4"]}
`)
	w := f.serve(chromeNav())
	if w.Code != http.StatusOK || f.backend.Load() != 1 {
		t.Fatalf("status %d, backend hits %d; an allow rule should proxy an uncleared navigation", w.Code, f.backend.Load())
	}
	evs := f.events("ALLOW", "rule_allow")
	if len(evs) != 1 || evs[0].Rule != "let-partner-in" {
		t.Fatalf("ALLOW rule_allow events = %+v, want one naming let-partner-in", evs)
	}
}

func TestRuleBlockServesBlockPage(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: no-admin
    mode: enforce
    action: block
    match: {paths: [{prefix: /admin}]}
`)
	r := chromeNav()
	r.URL.Path = "/admin/login"
	w := f.serve(r)
	if w.Code != http.StatusForbidden || f.backend.Load() != 0 {
		t.Fatalf("status %d, backend hits %d; a block rule should serve the block page without proxying", w.Code, f.backend.Load())
	}
	evs := f.events("BLOCK", "rule_block")
	if len(evs) != 1 || evs[0].Rule != "no-admin" {
		t.Fatalf("BLOCK rule_block events = %+v, want one naming no-admin", evs)
	}
	// Other paths are unaffected.
	if w := f.serve(chromeNav()); w.Code == http.StatusForbidden {
		t.Errorf("/page was blocked by a rule for /admin")
	}
}

func TestBlockRuleCoversPublicPathsAndClearedClients(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: no-robots
    mode: enforce
    action: block
    match: {paths: [{exact: /robots.txt}]}
  - id: ban-ip
    mode: enforce
    action: block
    match: {ips: ["5.6.7.8"]}
`)
	r := chromeNav()
	r.URL.Path = "/robots.txt"
	if w := f.serve(r); w.Code != http.StatusForbidden || f.backend.Load() != 0 {
		t.Errorf("/robots.txt: status %d, backend hits %d; a block rule must run before the public-path pass", w.Code, f.backend.Load())
	}

	// A client holding a valid clearance is still blocked by an IP rule.
	issuing := chromeNav()
	issuing.RemoteAddr = "5.6.7.8:1234"
	w := httptest.NewRecorder()
	f.h.cookies.Issue(w, "5.6.7.8", issuing)
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no clearance cookie issued")
	}
	cleared := fromIP("5.6.7.8")
	for _, c := range cookies {
		cleared.AddCookie(c)
	}
	if _, valid := f.h.cookies.Check(cleared, "5.6.7.8"); !valid {
		t.Fatal("test setup: the clearance cookie is not valid for this client")
	}
	if w := f.serve(cleared); w.Code != http.StatusForbidden || f.backend.Load() != 0 {
		t.Errorf("cleared client: status %d, backend hits %d; a block rule must override a valid clearance", w.Code, f.backend.Load())
	}
}

func TestChallengeRuleRaisesDispatchTier(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: puzzle-the-lot
    mode: enforce
    action: challenge
    tier: prism
    match: {paths: [{prefix: /}]}
`)
	w := f.serve(chromeNav())
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), f.h.prismPath+"?return=") {
		t.Fatalf("status %d Location %q, want a redirect to %s", w.Code, w.Header().Get("Location"), f.h.prismPath)
	}
	evs := f.events("CHALLENGE", "rule_challenge")
	if len(evs) != 1 || evs[0].Rule != "puzzle-the-lot" || evs[0].Tier != 4 {
		t.Fatalf("CHALLENGE rule_challenge events = %+v, want one naming puzzle-the-lot at tier prism", evs)
	}
}

func TestChallengeRuleNeverRechallengesCleared(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: puzzle-the-lot
    mode: enforce
    action: challenge
    tier: prism
    match: {paths: [{prefix: /}]}
`)
	r := chromeNav()
	for _, c := range issueClearance(t, &Handler{cookies: f.h.cookies}, chromeNav()) {
		r.AddCookie(c)
	}
	w := f.serve(r)
	if w.Code != http.StatusOK || f.backend.Load() != 1 {
		t.Fatalf("status %d, backend hits %d; a cleared client must not be re-challenged by a challenge rule", w.Code, f.backend.Load())
	}
	if evs := f.events("CHALLENGE", "rule_challenge"); len(evs) != 0 {
		t.Errorf("unexpected rule_challenge events: %+v", evs)
	}
}

func TestLogModeRuleAnnotatesEvent(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: watch-admin
    mode: log
    action: block
    match: {paths: [{prefix: /}]}
`)
	w := f.serve(chromeNav())
	if w.Code != http.StatusFound || f.backend.Load() != 0 {
		t.Fatalf("status %d, backend hits %d; a log-mode block must not change the outcome (pulse redirect expected)", w.Code, f.backend.Load())
	}
	evs := f.store.Recent(0, "CHALLENGE")
	if len(evs) != 1 {
		t.Fatalf("CHALLENGE events = %+v, want 1", evs)
	}
	if got := evs[0].LoggedRules; len(got) != 1 || got[0] != "watch-admin" {
		t.Errorf("LoggedRules = %v, want [watch-admin]", got)
	}
	if evs[0].Rule != "" || evs[0].Reason == "rule_block" {
		t.Errorf("a log-only match must not appear as the enforced rule: %+v", evs[0])
	}
}

func TestRulesNeverApplyToPrivateIPs(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: block-v4
    mode: enforce
    action: block
    match: {ips: ["0.0.0.0/0"]}
  - id: block-v6
    mode: enforce
    action: block
    match: {ips: ["::/0"]}
`)
	for _, addr := range []string{"127.0.0.1", "192.168.1.5", "[::1]"} {
		r := chromeNav()
		r.RemoteAddr = addr + ":1234"
		before := f.backend.Load()
		if w := f.serve(r); w.Code != http.StatusOK || f.backend.Load() != before+1 {
			t.Errorf("%s: status %d, backend hits +%d; private addresses must be proxied", addr, w.Code, f.backend.Load()-before)
		}
	}
	if evs := f.events("BLOCK", "rule_block"); len(evs) != 0 {
		t.Errorf("rule events for private IPs: %+v", evs)
	}
	// The same rules do block a public address.
	if w := f.serve(chromeNav()); w.Code != http.StatusForbidden {
		t.Errorf("public address: status %d, want 403 (the rules should apply to it)", w.Code)
	}
}

func TestBadRulesFileKeepsServing(t *testing.T) {
	f := newRulesFixture(t, "rules:\n  - id: Bad ID\n    action: nonsense\n")
	if f.h.Rules().LoadErr() == "" {
		t.Error("LoadErr is empty for an invalid rules.yaml")
	}
	w := f.serve(chromeNav())
	if w.Code != http.StatusFound {
		t.Errorf("status %d, want the normal pulse redirect while the rules file is broken", w.Code)
	}
	r := chromeNav()
	r.RemoteAddr = "127.0.0.1:1234"
	if w := f.serve(r); w.Code != http.StatusOK {
		t.Errorf("loopback: status %d, want 200", w.Code)
	}
}

func TestLogModeRuleRidesClearanceEvent(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: watch-all
    mode: log
    action: log
    match: {paths: [{prefix: /}]}
`)
	r := chromeNav()
	for _, c := range issueClearance(t, &Handler{cookies: f.h.cookies}, chromeNav()) {
		r.AddCookie(c)
	}
	if w := f.serve(r); w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	evs := f.events("ALLOW", "clearance")
	if len(evs) != 1 || len(evs[0].LoggedRules) != 1 || evs[0].LoggedRules[0] != "watch-all" {
		t.Fatalf("clearance events = %+v, want one carrying LoggedRules [watch-all]", evs)
	}
}

func TestLoggedRulesSplitRollupRuns(t *testing.T) {
	a := rollupKey{"ALLOW", "clearance", "1.2.3.4", "h", "ua", ""}
	b := rollupKey{"ALLOW", "clearance", "1.2.3.4", "h", "ua", "watch-admin"}
	if a == b {
		t.Fatal("rollup keys that differ in log-only matches must not be equal")
	}
}

func TestRuleLookupsTreatASNZeroAsUnknown(t *testing.T) {
	tests := []struct {
		name      string
		rec       asn.Record
		err       error
		wantASN   uint
		wantKnown bool
		wantDC    bool
		dcKnown   bool
	}{
		{"datacenter network", asn.Record{ASN: 64496, Datacenter: true}, nil, 64496, true, true, true},
		{"ordinary network", asn.Record{ASN: 64497}, nil, 64497, true, false, true},
		{"ASN 0 is unlisted or no database", asn.Record{}, nil, 0, false, false, false},
		{"unrouted, but a published cloud range", asn.Record{Classes: []string{"hosting"}, Datacenter: true}, nil, 0, false, true, true},
		{"lookup error", asn.Record{ASN: 64496, Datacenter: true}, fmt.Errorf("boom"), 0, false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			l := &ruleLookups{
				ip: net.ParseIP("203.0.113.9"),
				find: func(net.IP) (asn.Record, error) {
					calls++
					return tc.rec, tc.err
				},
			}
			if a, ok := l.lookup(); a != tc.wantASN || ok != tc.wantKnown {
				t.Errorf("lookup() = %d, %v; want %d, %v", a, ok, tc.wantASN, tc.wantKnown)
			}
			if dc, known := l.datacenter(); dc != tc.wantDC || known != tc.dcKnown {
				t.Errorf("datacenter() = %v, %v; want %v, %v", dc, known, tc.wantDC, tc.dcKnown)
			}
			l.country()
			l.network()
			if calls != 1 {
				t.Errorf("lookups = %d, want 1 (memoised)", calls)
			}
		})
	}
}

// With no network database (as in this fixture) every ASN lookup is 0, so a
// datacenter rule of either polarity must not match.
func TestDatacenterRulesIgnoreUnknownNetwork(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: not-dc
    mode: enforce
    action: block
    match: {datacenter: false}
  - id: dc
    mode: enforce
    action: block
    match: {datacenter: true}
`)
	if w := f.serve(chromeNav()); w.Code == http.StatusForbidden {
		t.Fatalf("status %d; a datacenter rule must not match when the network is unknown", w.Code)
	}
	if evs := f.events("BLOCK", "rule_block"); len(evs) != 0 {
		t.Errorf("rule_block events for an unknown network: %+v", evs)
	}
}

func TestLogModeRuleRecordsPublicPathAndFont(t *testing.T) {
	const watchAll = `
rules:
  - id: watch-all
    mode: log
    action: log
    match: {paths: [{prefix: /}]}
`
	tests := []struct {
		name, path, reason string
		wantStatus         int
	}{
		{"public path", "/robots.txt", "public_path", http.StatusOK},
		{"favicon", "/favicon.ico", "public_path", http.StatusOK},
		{"font", "/loupe/fonts/dmmono-300.woff2", "font", http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRulesFixture(t, watchAll)
			r := chromeNav()
			r.URL.Path = tc.path
			if w := f.serve(r); w.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d", w.Code, tc.wantStatus)
			}
			evs := f.events("ALLOW", tc.reason)
			if len(evs) != 1 || len(evs[0].LoggedRules) != 1 || evs[0].LoggedRules[0] != "watch-all" {
				t.Fatalf("%s events = %+v, want one carrying LoggedRules [watch-all]", tc.reason, evs)
			}
			if evs[0].Rule != "" {
				t.Errorf("Rule = %q; a log-only match is not the enforced rule", evs[0].Rule)
			}
		})
	}
}

func TestPublicPathRecordsNothingWithoutLogMatch(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: watch-admin
    mode: log
    action: log
    match: {paths: [{prefix: /admin}]}
`)
	r := chromeNav()
	r.URL.Path = "/robots.txt"
	if w := f.serve(r); w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if evs := f.store.Recent(0, ""); len(evs) != 0 {
		t.Errorf("events = %+v; public files are not logged unless a log-only rule matched", evs)
	}
}

// With no rules, runRules is on every request's path and must cost nothing.
func TestRunRulesEmptySetAllocatesNothing(t *testing.T) {
	h := &Handler{rules: rules.NewManager("")}
	r := chromeNav()
	ip := net.ParseIP("203.0.113.9")
	w := httptest.NewRecorder()
	if allocs := testing.AllocsPerRun(100, func() {
		if _, done := h.runRules(w, r, ip); done {
			t.Fatal("an empty rule set answered the request")
		}
	}); allocs != 0 {
		t.Errorf("runRules with an empty set allocates %v times per request, want 0", allocs)
	}
	h.rules = nil
	if _, done := h.runRules(w, r, ip); done {
		t.Error("a nil manager answered the request")
	}
}

func BenchmarkRunRulesEmpty(b *testing.B) {
	h := &Handler{rules: rules.NewManager("")}
	r := chromeNav()
	ip := net.ParseIP("203.0.113.9")
	w := httptest.NewRecorder()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.runRules(w, r, ip)
	}
}

// A broad allow rule matches every asset and API call, so only page
// navigations get a journal line. The event is rolled up either way.
func TestRuleAllowJournalLineOnlyForNavigations(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: let-all-in
    mode: enforce
    action: allow
    match: {paths: [{prefix: /}]}
`)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	asset := fromIP("1.2.3.4")
	asset.URL.Path = "/app.js"
	asset.Header.Set("Sec-Fetch-Dest", "script")
	asset.Header.Set("Accept", "*/*")
	if w := f.serve(asset); w.Code != http.StatusOK {
		t.Fatalf("asset: status %d", w.Code)
	}
	if strings.Contains(buf.String(), "ALLOW rule=") {
		t.Errorf("a non-navigation request was journaled:\n%s", buf.String())
	}

	if w := f.serve(fromIP("1.2.3.4")); w.Code != http.StatusOK {
		t.Fatalf("navigation: status %d", w.Code)
	}
	if !strings.Contains(buf.String(), "ALLOW rule=let-all-in") {
		t.Errorf("a navigation must be journaled, log:\n%s", buf.String())
	}
	if evs := f.events("ALLOW", "rule_allow"); len(evs) != 2 {
		t.Errorf("rule_allow events = %d, want 2 (journal line or not, the event is recorded)", len(evs))
	}
}

func TestRulesTestEndpointDoesNotProxy(t *testing.T) {
	f := newRulesFixture(t, `rules:
  - id: watch-wp
    action: log
    match: {paths: [{prefix: /wp-}]}
  - id: block-wp
    mode: enforce
    action: block
    match: {paths: [{prefix: /wp-}]}
`)
	r := httptest.NewRequest("GET", "/wp-login.php", nil)
	got := f.h.TestRules(r, net.ParseIP("203.0.113.9"))
	if got.Hit == nil || got.Hit.ID != "block-wp" || got.Hit.Action != "block" {
		t.Fatalf("hit = %+v, want block-wp", got.Hit)
	}
	if len(got.Logged) != 1 || got.Logged[0] != "watch-wp" {
		t.Fatalf("logged = %v, want [watch-wp]", got.Logged)
	}
	if got.Facts == nil {
		t.Fatal("no facts")
	}
	if n := f.backend.Load(); n != 0 {
		t.Fatalf("backend saw %d requests, want none", n)
	}
	if n := len(f.store.Recent(10, "")); n != 0 {
		t.Fatalf("dry run recorded %d events, want none", n)
	}
	if p := f.h.TestRules(r, net.ParseIP("192.168.1.5")); p.Hit != nil || p.Skipped == "" {
		t.Fatalf("private address = %+v, want skipped", p)
	}
}

// A rate limit counts cleared clients too: /login at 2 a minute holds for
// everyone, and the client over it gets a 429 with Retry-After.
func TestRateLimitAppliesToClearedClients(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: login-limit
    mode: enforce
    action: rate_limit
    limit: {requests: 2, period: 1m}
    match: {paths: [{exact: /login}]}
`)
	clearance := issueClearance(t, &Handler{cookies: f.h.cookies}, chromeNav())
	req := func() *http.Request {
		r := chromeNav()
		r.URL.Path = "/login"
		for _, c := range clearance {
			r.AddCookie(c)
		}
		return r
	}
	for i := range 2 {
		if w := f.serve(req()); w.Code != http.StatusOK {
			t.Fatalf("request %d: status %d, want it proxied within the limit", i+1, w.Code)
		}
	}
	w := f.serve(req())
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "30" {
		t.Fatalf("3rd request: status %d Retry-After %q, want 429 and 30", w.Code, w.Header().Get("Retry-After"))
	}
	if f.backend.Load() != 2 {
		t.Errorf("backend hits %d, want 2", f.backend.Load())
	}
	if evs := f.events("LIMIT", "rule_rate"); len(evs) != 1 || evs[0].Rule != "login-limit" {
		t.Errorf("LIMIT rule_rate events = %+v, want one naming login-limit", evs)
	}
}

// A rate limit that challenges raises the tier for an uncleared client.
func TestRateLimitChallengeRaisesTier(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: slow-down
    mode: enforce
    action: rate_limit
    tier: prism
    limit: {requests: 1, period: 1m, then: challenge}
    match: {paths: [{prefix: /}]}
`)
	f.serve(chromeNav())
	w := f.serve(chromeNav())
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), f.h.prismPath+"?return=") {
		t.Fatalf("status %d Location %q, want a redirect to %s", w.Code, w.Header().Get("Location"), f.h.prismPath)
	}
}

// Over a rate limit, a browser navigating gets a page in its language with
// the wait; an API call or asset gets the plain 429.
func TestRateLimitedPage(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: login-limit
    mode: enforce
    action: rate_limit
    limit: {requests: 1, period: 1m}
    match: {paths: [{exact: /login}]}
`)
	nav := func() *http.Request {
		r := chromeNav()
		r.URL.Path = "/login"
		r.Header.Set("Accept-Language", "de")
		return r
	}
	f.serve(nav())
	w := f.serve(nav())
	body := w.Body.String()
	if w.Code != http.StatusTooManyRequests || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("navigation: status %d, Content-Type %q, want a 429 page", w.Code, w.Header().Get("Content-Type"))
	}
	for _, want := range []string{`lang="de"`, "Ihre Anfragen werden gerade begrenzt.", `<span id="n">60</span> Sekunden`, "Erneut versuchen"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if w.Header().Get("Retry-After") != "60" || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("headers %v, want Retry-After 60 and no-store", w.Header())
	}

	api := nav()
	api.Header.Set("Sec-Fetch-Dest", "empty")
	api.Header.Set("Accept", "application/json")
	w = f.serve(api)
	if w.Code != http.StatusTooManyRequests || strings.Contains(w.Body.String(), "<html") || w.Header().Get("Retry-After") == "" {
		t.Fatalf("API call: status %d body %q, want a plain 429 with Retry-After", w.Code, w.Body)
	}
}
