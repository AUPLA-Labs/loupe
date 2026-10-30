package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/rules"
)

// rulesServer is a versioned admin server with a rules manager on a temp
// rules.yaml holding initial ("" = no file).
func rulesServer(t *testing.T, initial string) (http.Handler, *Server, *rules.Manager) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if initial != "" {
		if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h, srv, _, _ := versionedServer(t, filepath.Join(dir, "config.yaml"))
	m := rules.NewManager(path)
	srv.SetRules(m, func(r *http.Request, ip net.IP) RulesTest { return RulesTest{} })
	return h, srv, m
}

func getRules(t *testing.T, h http.Handler) (etag string, body map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/rules", nil))
	if w.Code != 200 {
		t.Fatalf("GET /api/rules: %d %s", w.Code, w.Body)
	}
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	return w.Header().Get("ETag"), body
}

func postRules(h http.Handler, body, etag string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/rules", strings.NewReader(body))
	r.Header.Set(csrfHeader, "1")
	if etag != "" {
		r.Header.Set("If-Match", etag)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRulesSaveRejectsCompileErrors(t *testing.T) {
	h, _, m := rulesServer(t, "")
	w := postRules(h, `{"rules":[{"id":"ok","action":"block","match":{"methods":["POST"]}},{"id":"bad","action":"block","match":{"paths":[{"regex":"("}]}}]}`, "")
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("save = %d %s, want 422", w.Code, w.Body)
	}
	var resp struct {
		Errors []ruleErrorJSON `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body %q: %v", w.Body, err)
	}
	if len(resp.Errors) != 1 || resp.Errors[0].Index != 1 || resp.Errors[0].ID != "bad" || resp.Errors[0].Field != "match.paths[0].regex" {
		t.Fatalf("errors = %+v, want one on rule 1 (bad), field match.paths[0].regex", resp.Errors)
	}
	if _, err := os.Stat(m.Path()); !os.IsNotExist(err) {
		t.Fatalf("rules.yaml was written despite the error (stat err %v)", err)
	}
}

func TestRulesSaveETagConflict(t *testing.T) {
	h, srv, m := rulesServer(t, "rules: []\n")
	etag, _ := getRules(t, h)
	// A hand edit lands after the editor loaded the file.
	hand := "rules:\n  - id: hand\n    action: block\n    match: {methods: [PUT]}\n"
	os.WriteFile(m.Path(), []byte(hand), 0o600) //nolint:errcheck
	body := `{"rules":[{"id":"mine","action":"block","match":{"methods":["POST"]}}]}`
	if w := postRules(h, body, etag); w.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale save = %d %s, want 412", w.Code, w.Body)
	}
	if got, _ := os.ReadFile(m.Path()); string(got) != hand {
		t.Fatalf("file = %q, want the hand edit kept", got)
	}
	etag, _ = getRules(t, h)
	w := postRules(h, body, etag)
	if w.Code != 200 {
		t.Fatalf("fresh save = %d %s", w.Code, w.Body)
	}
	if rs := m.Rules(); len(rs) != 1 || rs[0].ID != "mine" {
		t.Fatalf("live rules = %+v, want the saved one applied at once", rs)
	}
	// The hand edit it replaced is in the history, so the save can be undone.
	vs, _ := srv.history.Load().List("rules")
	if len(vs) != 2 {
		t.Fatalf("rules versions = %d, want 2 (the hand edit, then the save)", len(vs))
	}
	if old, _ := srv.history.Load().Get("rules", vs[1].ID); string(old) != hand {
		t.Fatalf("older version = %q, want the hand edit", old)
	}
}

func TestQuickBlockCreatesExpiringRule(t *testing.T) {
	h, _, m := rulesServer(t, "rules:\n  - id: partner\n    mode: enforce\n    action: allow\n    match: {ips: [203.0.113.0/24]}\n")
	before := time.Now()
	w := postJSON(h, "/api/rules/quick-block", `{"ip":"203.0.113.7","duration":"24h","note":"scraping"}`)
	if w.Code != 200 {
		t.Fatalf("quick block = %d %s", w.Code, w.Body)
	}
	rs := m.Rules()
	if len(rs) != 2 || rs[1].ID != "partner" {
		t.Fatalf("rules = %+v, want the block first, above the allow", rs)
	}
	r := rs[0]
	if r.Mode != rules.ModeEnforce || r.Action != rules.ActionBlock || len(r.Match.IPs) != 1 || r.Match.IPs[0] != "203.0.113.7" || r.Note != "scraping" {
		t.Fatalf("rule = %+v, want an enforced block of 203.0.113.7", r)
	}
	if !strings.HasPrefix(r.ID, "block-203-0-113-7-") {
		t.Fatalf("id = %q", r.ID)
	}
	if r.Expires == nil || r.Expires.Sub(before) < 23*time.Hour || r.Expires.Sub(before) > 25*time.Hour {
		t.Fatalf("expires = %v, want about 24h from now", r.Expires)
	}
	for _, bad := range []string{`{"ip":"203.0.113.7","duration":"2h"}`, `{"ip":"nope","duration":"1h"}`} {
		if w := postJSON(h, "/api/rules/quick-block", bad); w.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", bad, w.Code)
		}
	}
	if w := postJSON(h, "/api/rules/quick-block", `{"ip":"192.168.1.5","duration":"1h"}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("private address = %d, want 422", w.Code)
	}
}

func TestQuickBlockRefusesBrokenFile(t *testing.T) {
	h, _, m := rulesServer(t, "rules: [\n")
	if w := postJSON(h, "/api/rules/quick-block", `{"ip":"203.0.113.7","duration":"1h"}`); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("quick block over a broken file = %d %s, want 422", w.Code, w.Body)
	}
	if got, _ := os.ReadFile(m.Path()); string(got) != "rules: [\n" {
		t.Fatalf("file = %q, want it untouched", got)
	}
}

func TestRuleHitsCountsSummaryEvents(t *testing.T) {
	s := newTestStore(t, 10)
	now := time.Now()
	s.Add(Event{Time: now.Add(-48 * time.Hour), Rule: "block-a"}) // outside the window
	s.Add(Event{Time: now, Rule: "block-a", Count: 5})
	s.Add(Event{Time: now, Rule: "block-a", LoggedRules: []string{"watch"}})
	s.Add(Event{Time: now, LoggedRules: []string{"watch"}, Count: 3})
	enforced, logged := s.RuleHits(now.Add(-24 * time.Hour))
	if enforced["block-a"] != 6 || logged["watch"] != 4 {
		t.Fatalf("enforced = %v, logged = %v, want block-a 6 and watch 4", enforced, logged)
	}
}

func TestRulesRestoreFromHistory(t *testing.T) {
	h, srv, m := rulesServer(t, "")
	first := `{"rules":[{"id":"one","action":"block","match":{"methods":["POST"]}}]}`
	if w := postRules(h, first, ""); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	vs, _ := srv.history.Load().List("rules")
	if w := postRules(h, `{"rules":[]}`, ""); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	w := postJSON(h, "/api/history/restore", `{"file":"rules","version":"`+vs[0].ID+`"}`)
	if w.Code != 200 {
		t.Fatalf("restore = %d %s", w.Code, w.Body)
	}
	if rs := m.Rules(); len(rs) != 1 || rs[0].ID != "one" {
		t.Fatalf("live rules = %+v, want the restored version applied", rs)
	}
}

// The editor saves conditions as any groups; an error in one points at its
// group and row.
func TestRulesSaveAnyGroups(t *testing.T) {
	h, _, m := rulesServer(t, "")
	w := postRules(h, `{"rules":[{"id":"r","action":"block","any":[{"all":[{"paths":[{"prefix":"/a"}]}]},{"all":[{"methods":["POST"]},{"user_agents":[{"regex":"("}],"not":true}]}]}]}`, "")
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `"field":"any[1].all[1].user_agents[0].regex"`) {
		t.Fatalf("save = %d %s, want 422 on any[1].all[1].user_agents[0].regex", w.Code, w.Body)
	}
	w = postRules(h, `{"rules":[{"id":"r","action":"block","any":[{"all":[{"paths":[{"prefix":"/a"}]}]},{"all":[{"methods":["POST"]},{"ips":["203.0.113.0/24"],"not":true}]}]}]}`, "")
	if w.Code != http.StatusOK {
		t.Fatalf("save = %d %s", w.Code, w.Body)
	}
	rs := m.Rules()
	if len(rs) != 1 || len(rs[0].Any) != 2 || !rs[0].Any[1].All[1].Not {
		t.Fatalf("live rules = %+v", rs)
	}
}
