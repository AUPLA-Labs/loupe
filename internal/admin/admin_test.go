package admin

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/bots"
	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
)

func newTestStore(t *testing.T, capacity int) *Store {
	t.Helper()
	s, err := NewStore(capacity, "")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStatsForBucketsAndPreviousWindow(t *testing.T) {
	s := newTestStore(t, 100)
	now := time.Date(2026, 10, 18, 12, 30, 0, 0, time.UTC)
	w := LookupWindow("1h")

	s.Add(Event{Time: now.Add(-90 * time.Minute), Action: "BLOCK", IP: "9.9.9.9"}) // previous window
	s.Add(Event{Time: now.Add(-59 * time.Minute), Action: "BLOCK", IP: "1.1.1.1", ASN: 13335, Org: "CF", Path: "/a", Reasons: []string{"sig"}})
	s.Add(Event{Time: now.Add(-time.Minute), Action: "ALLOW", IP: "1.1.1.1", Host: "h"})
	s.Add(Event{Time: now, Action: "CHALLENGE", IP: "2.2.2.2", Reason: "bot_ua"})

	st := s.StatsFor(w, now)
	if st.Total != 3 || st.PrevTotal != 1 {
		t.Fatalf("total=%d prev=%d, want 3 and 1", st.Total, st.PrevTotal)
	}
	if st.UniqueIPs != 2 || st.PrevUniqueIPs != 1 {
		t.Fatalf("unique=%d prev=%d, want 2 and 1", st.UniqueIPs, st.PrevUniqueIPs)
	}
	if len(st.Series["BLOCK"]) != 60 {
		t.Fatalf("series length %d, want 60", len(st.Series["BLOCK"]))
	}
	if got := st.Series["CHALLENGE"][59]; got != 1 {
		t.Fatalf("current-minute bucket = %d, want 1", got)
	}
	if !st.End.Equal(now.Add(time.Minute)) || !st.Start.Equal(now.Add(-59*time.Minute)) {
		t.Fatalf("window %v–%v not aligned to the current bucket", st.Start, st.End)
	}
	if len(st.TopIPs) == 0 || st.TopIPs[0].IP != "1.1.1.1" || st.TopIPs[0].Blocked != 1 || st.TopIPs[0].ASN != 13335 {
		t.Fatalf("top IPs = %+v", st.TopIPs)
	}
	if len(st.TopSignals) != 1 || st.TopSignals[0].Key != "sig" {
		t.Fatalf("top signals = %+v", st.TopSignals)
	}
}

func TestLookupWindowDefaults(t *testing.T) {
	if LookupWindow("bogus").Name != "24h" {
		t.Fatal("unknown window should fall back to 24h")
	}
}

func TestQueryFiltersAndPaginates(t *testing.T) {
	s := newTestStore(t, 100)
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 10; i++ {
		act := "ALLOW"
		if i%2 == 0 {
			act = "BLOCK"
		}
		s.Add(Event{Time: base.Add(time.Duration(i) * time.Minute), Action: act, IP: "10.0.0.1", Path: "/p", UA: "curl/8"})
	}
	s.Add(Event{Time: base.Add(time.Hour), Action: "BLOCK", IP: "10.0.0.2", Reasons: []string{"Canvas_Noise"}})

	res := s.Query(Query{Action: "BLOCK", IP: "10.0.0.1", Limit: 3})
	if len(res.Events) != 3 || !res.More {
		t.Fatalf("got %d events more=%v, want 3 and true", len(res.Events), res.More)
	}
	if !res.Events[0].Time.Before(res.Events[2].Time) {
		t.Fatal("events should be oldest first")
	}
	next := s.Query(Query{Action: "BLOCK", IP: "10.0.0.1", Limit: 3, Before: res.Events[0].Time})
	if len(next.Events) != 2 || next.More {
		t.Fatalf("second page: %d events more=%v, want 2 and false", len(next.Events), next.More)
	}

	if got := s.Query(Query{Text: "canvas"}).Events; len(got) != 1 || got[0].IP != "10.0.0.2" {
		t.Fatalf("signal text search = %+v", got)
	}
	if got := s.Query(Query{Text: "curl"}).Events; len(got) != 10 {
		t.Fatalf("UA text search returned %d, want 10", len(got))
	}
}

func TestParseQuery(t *testing.T) {
	q := ParseQuery(url.Values{"action": {"block"}, "asn": {"AS13335"}, "q": {" Foo "}, "limit": {"5000"}})
	if q.Action != "BLOCK" || q.ASN != 13335 || q.Text != "foo" || q.limit() != 1000 {
		t.Fatalf("parsed %+v (limit %d)", q, q.limit())
	}
}

func TestProfile(t *testing.T) {
	s := newTestStore(t, 100)
	t0 := time.Now().Add(-time.Hour)
	s.Add(Event{Time: t0, Action: "CHALLENGE", IP: "1.2.3.4", ASN: 64500, Org: "Example"})
	s.Add(Event{Time: t0.Add(time.Minute), Action: "BLOCK", IP: "1.2.3.4", UA: "x"})
	s.Add(Event{Time: t0.Add(2 * time.Minute), Action: "ALLOW", IP: "5.6.7.8"})

	p := s.Profile("1.2.3.4")
	if p.Total != 2 || p.ByAction["BLOCK"] != 1 || p.ASN != 64500 {
		t.Fatalf("profile = %+v", p)
	}
	if !p.First.Equal(t0) || !p.Last.Equal(t0.Add(time.Minute)) {
		t.Fatalf("first/last = %v/%v", p.First, p.Last)
	}
	if len(p.Events) != 2 || p.Events[0].Action != "CHALLENGE" {
		t.Fatalf("events = %+v", p.Events)
	}
}

func TestBufferInfoWraps(t *testing.T) {
	s := newTestStore(t, 3)
	t0 := time.Now()
	for i := 0; i < 5; i++ {
		s.Add(Event{Time: t0.Add(time.Duration(i) * time.Second), Action: "ALLOW"})
	}
	b := s.Buffer()
	if b.Size != 3 || !b.Oldest.Equal(t0.Add(2*time.Second)) || !b.Newest.Equal(t0.Add(4*time.Second)) {
		t.Fatalf("buffer = %+v", b)
	}
}

func TestCSRFGuard(t *testing.T) {
	h := csrfGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	cases := []struct {
		method, header, site string
		want                 int
	}{
		{"GET", "", "cross-site", http.StatusNoContent},
		{"POST", "", "", http.StatusForbidden},
		{"POST", "1", "cross-site", http.StatusForbidden},
		{"POST", "1", "same-origin", http.StatusNoContent},
		{"POST", "1", "", http.StatusNoContent},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "/api/restart", nil)
		if c.header != "" {
			r.Header.Set(csrfHeader, c.header)
		}
		if c.site != "" {
			r.Header.Set("Sec-Fetch-Site", c.site)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s header=%q site=%q: got %d, want %d", c.method, c.header, c.site, w.Code, c.want)
		}
	}
}

func TestConfigSaveRejectsStaleETagAndInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), path, AuthOptions{})
	h := srv.Handler()

	post := func(body, etag string) int {
		r := httptest.NewRequest("POST", "/api/config", strings.NewReader(body))
		r.Header.Set(csrfHeader, "1")
		if etag != "" {
			r.Header.Set("If-Match", etag)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	if code := post("listen: [unclosed", ""); code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid YAML: got %d, want 422", code)
	}
	if code := post("listen: [unclosed", configETag([]byte("other"))); code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid YAML is reported before the ETag check: got %d", code)
	}
	if code := post("{}\n", configETag([]byte("other"))); code != http.StatusPreconditionFailed {
		t.Fatalf("stale ETag: got %d, want 412", code)
	}
	if b, _ := os.ReadFile(path); string(b) != "original" {
		t.Fatalf("rejected save modified the file: %q", b)
	}

	if code := post("{}\n", configETag([]byte("original"))); code != http.StatusNoContent {
		t.Fatalf("valid save: got %d, want 204", code)
	}
	if b, _ := os.ReadFile(path); string(b) != "{}\n" {
		t.Fatalf("saved file = %q", b)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("config.yaml.bak written (%v); history replaces it", err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{"=cmd()": "'=cmd()", "/path": "/path", "": "", "@x": "'@x"} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBotStatsAndFilter(t *testing.T) {
	s := newTestStore(t, 100)
	now := time.Now()
	s.Add(Event{Time: now.Add(-48 * time.Hour), Action: "ALLOW", Bot: "googlebot", BotStatus: "verified"})
	s.Add(Event{Time: now.Add(-time.Hour), Action: "ALLOW", Bot: "googlebot", BotStatus: "verified"})
	s.Add(Event{Time: now.Add(-time.Minute), Action: "BLOCK", Bot: "googlebot", BotStatus: "spoofed"})
	s.Add(Event{Time: now, Action: "ALLOW", IP: "1.1.1.1"})

	st := s.BotStats(now.Add(-24 * time.Hour))["googlebot"]
	if st == nil || st.Total != 2 || st.Allowed != 1 || st.Blocked != 1 || st.Verified != 1 || st.Spoofed != 1 {
		t.Fatalf("bot stats = %+v", st)
	}
	if got := s.Query(ParseQuery(url.Values{"bot": {"googlebot"}})).Events; len(got) != 3 {
		t.Fatalf("bot filter returned %d events, want 3", len(got))
	}
}

func TestSettingsSaveEditsInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	src := "# my config\ncookie_ttl: 86400  # a day\n\nabuse:\n  rate_limit:\n    rate: 1.0\n    burst: 15\nasn:\n  blocked_asns: []\n"
	os.WriteFile(path, []byte(src), 0600)
	h := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), path, AuthOptions{}).Handler()

	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/settings", strings.NewReader(body))
		r.Header.Set(csrfHeader, "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := post(`{"etag":` + strconv.Quote(configETag([]byte(src))) + `,"values":{"cookie_ttl":43200,"abuse.rate_limit.burst":30,"asn.blocked_asns":[{"asn":64500,"org":"Bad # Net"}]}}`)
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	got, _ := os.ReadFile(path)
	want := "# my config\ncookie_ttl: 43200  # 12 hours (renewal is a silent pulse)\n\nabuse:\n  rate_limit:\n    rate: 1.0\n    burst: 30\nasn:\n  blocked_asns:\n    - 64500  # Bad Net\n"
	if string(got) != want {
		t.Fatalf("file:\n%s\nwant:\n%s", got, want)
	}

	for body, code := range map[string]int{
		`{"values":{"listen":"0.0.0.0:1"}}`:                 http.StatusUnprocessableEntity, // not a form setting
		`{"values":{"cookie_ttl":5}}`:                       http.StatusUnprocessableEntity, // out of range
		`{"values":{"hardening.request_score.tier2":20}}`:   http.StatusUnprocessableEntity, // ordering
		`{"values":{"hardening.exploit_paths":["/x"]}}`:     http.StatusUnprocessableEntity, // too short
		`{"etag":"\"stale\"","values":{"cookie_ttl":3600}}`: http.StatusPreconditionFailed,
	} {
		if w := post(body); w.Code != code {
			t.Errorf("%s: got %d, want %d (%s)", body, w.Code, code, w.Body)
		}
	}
	if after, _ := os.ReadFile(path); string(after) != want {
		t.Fatal("a rejected save changed the file")
	}
}

func TestSettingsSaveLumen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	src := "lumen:\n  work: 100000\n"
	os.WriteFile(path, []byte(src), 0600)
	h := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), path, AuthOptions{}).Handler()
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/settings", strings.NewReader(body))
		r.Header.Set(csrfHeader, "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := post(`{"values":{"lumen.enforce":true,"lumen.memory_mb":16}}`); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	got, _ := os.ReadFile(path)
	for _, want := range []string{"  enforce: true\n", "  memory_mb: 16\n"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("file:\n%s\nwant it to contain %q", got, want)
		}
	}
	for body, code := range map[string]int{
		`{"values":{"lumen.enforce":"yes"}}`:     http.StatusUnprocessableEntity, // not a bool
		`{"values":{"lumen.pulse_work":200000}}`: http.StatusUnprocessableEntity, // pulse above challenge page
		`{"values":{"lumen.memory_mb":64}}`:      http.StatusUnprocessableEntity, // above the ceiling
		`{"values":{"lumen.max_level":0}}`:       http.StatusUnprocessableEntity, // out of range
	} {
		if w := post(body); w.Code != code {
			t.Errorf("%s: got %d, want %d (%s)", body, w.Code, code, w.Body)
		}
	}
}

func TestStatsLumenBreakdown(t *testing.T) {
	s := newTestStore(t, 100)
	now := time.Now()
	lvl := func(l int) *int { return &l }
	for _, e := range []Event{
		{Time: now, Action: "CHALLENGE", Lumen: lvl(0), LumenDispatch: true},
		{Time: now, Action: "CHALLENGE", Lumen: lvl(3), LumenDispatch: true},
		{Time: now, Action: "PASS", Lumen: lvl(0), LumenRate: 1e6, LumenSpaceMs: 40},
		{Time: now, Action: "PASS", Lumen: lvl(0), LumenRate: 3e6, LumenSpaceMs: 60},
		{Time: now, Action: "FAIL", Lumen: lvl(3), LumenRate: 2e6},
		{Time: now, Action: "ALLOW"},
	} {
		s.Add(e)
	}
	l := s.StatsFor(LookupWindow("1h"), now).Lumen
	if l.Challenged[0] != 1 || l.Challenged[3] != 1 || l.Passed[0] != 2 || l.Passed[3] != 0 || l.Answers[3] != 1 {
		t.Errorf("counts = %+v", l)
	}
	if l.Rate[0] != 2e6 || l.SpaceMs[0] != 50 || l.SpaceMs[3] != 0 {
		t.Errorf("medians: rate %v space %v", l.Rate, l.SpaceMs)
	}
}

func TestStoreRenamesLegacyReasonsOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	log := `{"t":"2026-05-13T20:48:03Z","action":"FAIL","ip":"1.2.3.4","reason":"altcha"}` + "\n" +
		`{"t":"2026-05-13T20:48:04Z","action":"CHALLENGE","ip":"1.2.3.4","reason":"request_score_altcha","reasons":["request_score_altcha","ua_malformed"]}` + "\n"
	if err := os.WriteFile(path, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(10, path)
	if err != nil {
		t.Fatal(err)
	}
	got := s.Recent(10, "")
	if len(got) != 2 {
		t.Fatalf("loaded %d events, want 2", len(got))
	}
	reasons := map[string]bool{}
	for _, e := range got {
		reasons[e.Reason] = true
		for _, r := range e.Reasons {
			reasons[r] = true
		}
	}
	for _, want := range []string{"pow_invalid", "request_score_lumen", "ua_malformed"} {
		if !reasons[want] {
			t.Errorf("missing %q after load: %v", want, reasons)
		}
	}
	if reasons["altcha"] || reasons["request_score_altcha"] {
		t.Errorf("legacy IDs survived the load: %v", reasons)
	}
	b, _ := os.ReadFile(path)
	if string(b) != log {
		t.Error("loading rewrote the log file")
	}
}

func TestAdminStreamOutlivesReadTimeout(t *testing.T) {
	store := newTestStore(t, 10)
	srv := NewServer(store, nil, "", AuthOptions{}).HTTPServer("")
	if srv.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout = %v, want 0: it would cut off /api/stream", srv.WriteTimeout)
	}
	srv.ReadTimeout = 200 * time.Millisecond

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	resp, err := http.Get("http://" + ln.Addr().String() + "/api/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r := bufio.NewReader(resp.Body)
	// ": connected" is written after the subscription exists.
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reading stream preamble: %v", err)
		}
		if strings.HasPrefix(line, ": connected") {
			break
		}
	}

	time.Sleep(600 * time.Millisecond) // well past ReadTimeout
	store.Add(Event{Time: time.Now(), Action: "BLOCK", IP: "1.2.3.4"})

	got := make(chan string, 1)
	go func() {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				got <- "error: " + err.Error()
				return
			}
			if strings.HasPrefix(line, "data: ") {
				got <- line
				return
			}
		}
	}()
	select {
	case line := <-got:
		if !strings.Contains(line, "1.2.3.4") {
			t.Fatalf("stream after ReadTimeout gave %q, want the event for 1.2.3.4", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event received after ReadTimeout elapsed")
	}
}

func TestAdminShutdownEndsOpenStream(t *testing.T) {
	srv := NewServer(newTestStore(t, 10), nil, "", AuthOptions{}).HTTPServer("")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	resp, err := http.Get("http://" + ln.Addr().String() + "/api/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil {
		t.Fatalf("reading stream preamble: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown with an open stream: %v (streams should end when it starts)", err)
	}
}

// versionedServer is an admin server over the config at path with history
// and audit both connected.
func versionedServer(t *testing.T, path string) (http.Handler, *Server, *config.History, *Audit) {
	t.Helper()
	srv := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), path, AuthOptions{})
	hist := config.NewHistory(filepath.Join(t.TempDir(), "history"), 10)
	a, _ := NewAudit("")
	srv.SetHistory(hist)
	srv.SetAudit(a)
	return srv.Handler(), srv, hist, a
}

func postJSON(h http.Handler, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set(csrfHeader, "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// wantVersion checks that the newest history version of name holds want and
// that the one audit entry carries its id.
func wantVersion(t *testing.T, hist *config.History, a *Audit, name string, want []byte) AuditEntry {
	t.Helper()
	vs, err := hist.List(name)
	if err != nil || len(vs) == 0 {
		t.Fatalf("history of %s = %v (%v), want the saved version", name, vs, err)
	}
	got, err := hist.Get(name, vs[0].ID)
	if err != nil || string(got) != string(want) {
		t.Fatalf("newest %s version = %q (%v), want %q", name, got, err, want)
	}
	entries := a.Recent(10, time.Time{})
	if len(entries) != 1 {
		t.Fatalf("audit entries = %+v, want exactly one", entries)
	}
	if entries[0].Version != vs[0].ID {
		t.Fatalf("audit version = %q, want the newest history id %q", entries[0].Version, vs[0].ID)
	}
	return entries[0]
}

func TestConfigSaveRecordsVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte("listen: \":8080\"\ncookie_ttl: 86400\n"), 0600)
	h, _, hist, a := versionedServer(t, path)

	next := "listen: \":8080\"\ncookie_ttl: 43200\n"
	if w := postJSON(h, "/api/config", next); w.Code != http.StatusNoContent {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	e := wantVersion(t, hist, a, "config", []byte(next))
	if e.Action != "config_save" || e.Target != "config.yaml" || e.Detail != "+1 −1 lines" {
		t.Fatalf("audit entry = %+v, want config_save of config.yaml with detail %q", e, "+1 −1 lines")
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("config.yaml.bak written (%v); history replaces it", err)
	}
}

func TestSettingsSaveRecordsVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte("abuse:\n  rate_limit:\n    rate: 1.0\n    burst: 15\n"), 0600)
	h, _, hist, a := versionedServer(t, path)

	if w := postJSON(h, "/api/settings", `{"values":{"abuse.rate_limit.burst":30}}`); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	saved, _ := os.ReadFile(path)
	e := wantVersion(t, hist, a, "config", saved)
	if e.Action != "settings_save" || !strings.Contains(e.Detail, "abuse.rate_limit.burst") {
		t.Fatalf("audit entry = %+v, want settings_save naming abuse.rate_limit.burst", e)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("config.yaml.bak written (%v); history replaces it", err)
	}
}

func TestConfigSaveSucceedsWhenHistoryUnwritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte("cookie_ttl: 86400\n"), 0600)
	blocker := filepath.Join(dir, "history")
	os.WriteFile(blocker, []byte("a file, not a directory"), 0600)
	srv := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), path, AuthOptions{})
	a, _ := NewAudit("")
	srv.SetHistory(config.NewHistory(blocker, 10))
	srv.SetAudit(a)

	if w := postJSON(srv.Handler(), "/api/config", "cookie_ttl: 43200\n"); w.Code != http.StatusNoContent {
		t.Fatalf("save with unwritable history: %d %s, want 204", w.Code, w.Body)
	}
	if b, _ := os.ReadFile(path); string(b) != "cookie_ttl: 43200\n" {
		t.Fatalf("config = %q, want the new contents", b)
	}
	entries := a.Recent(10, time.Time{})
	if len(entries) != 1 || entries[0].Action != "config_save" || entries[0].Version != "" {
		t.Fatalf("audit entries = %+v, want one config_save with no version", entries)
	}
}

func TestBotsPolicySaveRecordsVersion(t *testing.T) {
	dir := t.TempDir()
	m, err := bots.New(bots.Options{PolicyFile: filepath.Join(dir, "bots.yaml"), RangesDir: filepath.Join(dir, "ranges")})
	if err != nil {
		t.Fatal(err)
	}
	h, srv, hist, a := versionedServer(t, filepath.Join(dir, "config.yaml"))
	srv.SetBots(m)
	m.SetOnPolicyWritten(func(b []byte) {
		if _, err := hist.Save("bots", b); err != nil {
			t.Error(err)
		}
	})

	if w := postJSON(h, "/api/bots/policy", `{"categories":{"preview":"block"},"spoofed":"standard","unverifiable":"block","robots":{"mode":"off"}}`); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	onDisk, err := os.ReadFile(m.PolicyFile())
	if err != nil {
		t.Fatal(err)
	}
	e := wantVersion(t, hist, a, "bots", onDisk)
	// The initial file has no categories; the save adds the key and its one entry.
	if e.Action != "bots_policy" || e.Target != "bots.yaml" || e.Detail != "+2 −0 lines" {
		t.Fatalf("audit entry = %+v, want bots_policy of bots.yaml with detail %q", e, "+2 −0 lines")
	}
}

func TestBotsPolicySaveWithoutVersionLinksNothing(t *testing.T) {
	dir := t.TempDir()
	m, err := bots.New(bots.Options{PolicyFile: filepath.Join(dir, "bots.yaml"), RangesDir: filepath.Join(dir, "ranges")})
	if err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(dir, "history")
	os.WriteFile(blocker, []byte("a file, not a directory"), 0600)
	srv := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), filepath.Join(dir, "config.yaml"), AuthOptions{})
	a, _ := NewAudit("")
	hist := config.NewHistory(blocker, 10)
	srv.SetHistory(hist)
	srv.SetAudit(a)
	srv.SetBots(m)
	m.SetOnPolicyWritten(func(b []byte) { hist.Save("bots", b) }) // fails: the history dir is a file

	if w := postJSON(srv.Handler(), "/api/bots/policy", `{"categories":{"preview":"block"},"spoofed":"standard","unverifiable":"block","robots":{"mode":"off"}}`); w.Code != 200 {
		t.Fatalf("save with unwritable history: %d %s, want 200", w.Code, w.Body)
	}
	entries := a.Recent(10, time.Time{})
	if len(entries) != 1 || entries[0].Action != "bots_policy" || entries[0].Version != "" {
		t.Fatalf("audit entries = %+v, want one bots_policy with no version", entries)
	}
}

func TestBotsPolicySaveDoesNotLinkOlderVersion(t *testing.T) {
	dir := t.TempDir()
	m, err := bots.New(bots.Options{PolicyFile: filepath.Join(dir, "bots.yaml"), RangesDir: filepath.Join(dir, "ranges")})
	if err != nil {
		t.Fatal(err)
	}
	h, srv, hist, a := versionedServer(t, filepath.Join(dir, "config.yaml"))
	srv.SetBots(m)
	old, _ := os.ReadFile(m.PolicyFile())
	if _, err := hist.Save("bots", old); err != nil { // an earlier version; no hook is wired for the next save
		t.Fatal(err)
	}

	if w := postJSON(h, "/api/bots/policy", `{"categories":{"preview":"block"},"spoofed":"standard","unverifiable":"block","robots":{"mode":"off"}}`); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	if entries := a.Recent(10, time.Time{}); len(entries) != 1 || entries[0].Version != "" {
		t.Fatalf("audit entries = %+v, want the entry to link no version since the new bytes were never recorded", entries)
	}
}

// Request limits save into a config that has no limits section yet, and the
// config check refuses ones that can't be enforced.
func TestSettingsSaveLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte("cookie_ttl: 86400\n"), 0600)
	h := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), path, AuthOptions{}).Handler()
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/settings", strings.NewReader(body))
		r.Header.Set(csrfHeader, "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := post(`{"values":{"limits.max_body_bytes":10485760,"limits.upload_paths":["/upload/"],"limits.allowed_methods":["GET","POST","PROPFIND"]}}`); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	got, _ := os.ReadFile(path)
	cfg, err := config.LoadBytes(got)
	if err != nil {
		t.Fatalf("saved config doesn't load: %v\n%s", err, got)
	}
	if l := cfg.Limits; l.MaxBodyBytes != 10<<20 || len(l.UploadPaths) != 1 || len(l.AllowedMethods) != 3 || l.MaxURLBytes != 8192 {
		t.Fatalf("limits %+v from\n%s", l, got)
	}
	for body, code := range map[string]int{
		`{"values":{"limits.upload_paths":["upload/"]}}`: http.StatusUnprocessableEntity, // no leading slash
		`{"values":{"limits.allowed_methods":["G-T"]}}`:  http.StatusUnprocessableEntity, // not a method
		`{"values":{"limits.max_url_bytes":100}}`:        http.StatusUnprocessableEntity, // out of range
	} {
		if w := post(body); w.Code != code {
			t.Errorf("%s: got %d, want %d (%s)", body, w.Code, code, w.Body)
		}
	}
}
