package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
)

func TestAuditAddAndRecent(t *testing.T) {
	a, err := NewAudit("")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	t1, t2, t3 := t0, t0.Add(time.Second), t0.Add(2*time.Second)
	a.Add(AuditEntry{Time: t1, Action: "one"})
	a.Add(AuditEntry{Time: t2, Action: "two"})
	a.Add(AuditEntry{Time: t3, Action: "three"})

	got := a.Recent(10, time.Time{})
	if len(got) != 3 || got[0].Action != "three" || got[1].Action != "two" || got[2].Action != "one" {
		t.Fatalf("Recent(10) = %+v, want three, two, one", got)
	}
	got = a.Recent(1, t2)
	if len(got) != 1 || got[0].Action != "one" {
		t.Fatalf("Recent(1, t2) = %+v, want only the entry before t2", got)
	}
	if got := a.Recent(10, t1); len(got) != 0 {
		t.Fatalf("Recent before the oldest entry = %+v, want none", got)
	}
}

func TestAuditCapsMemoryAndPage(t *testing.T) {
	a, _ := NewAudit("")
	for i := 0; i < auditKeep+10; i++ {
		a.Add(AuditEntry{Time: time.Unix(int64(i), 0), Action: "x"})
	}
	if got := a.Recent(10000, time.Time{}); len(got) != auditMaxPage {
		t.Fatalf("Recent(10000) returned %d entries, want the cap of %d", len(got), auditMaxPage)
	}
	if len(a.entries) != auditKeep || !a.entries[0].Time.Equal(time.Unix(10, 0)) {
		t.Fatalf("held %d entries, oldest %v; want %d with the first 10 dropped", len(a.entries), a.entries[0].Time, auditKeep)
	}
}

func TestAuditPersistsAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := NewAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	a.Add(AuditEntry{Time: t0, User: "admin", IP: "192.0.2.1", Action: "config_save", Target: "config.yaml", Version: "v1"})
	a.Add(AuditEntry{Time: t0.Add(time.Second), Action: "restart"})

	b, err := NewAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	got := b.Recent(10, time.Time{})
	if len(got) != 2 || got[0].Action != "restart" || got[1].Version != "v1" || got[1].User != "admin" {
		t.Fatalf("after reopen: %+v, want both entries", got)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("audit file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(strings.Split(string(raw), "\n")[1], `"target"`) {
		t.Fatalf("empty target not omitted: %s", raw)
	}
}

func TestAuditRotatesLargeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	big := strings.Repeat(`{"t":"2026-10-01T12:00:00Z","action":"old"}`+"\n", 300000)
	if len(big) <= auditMaxFileBytes {
		t.Fatalf("test file is only %d bytes", len(big))
	}
	if err := os.WriteFile(path, []byte(big), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := NewAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Recent(10, time.Time{}); len(got) != 0 {
		t.Fatalf("a rotated log should start empty, got %d entries", len(got))
	}
	if fi, err := os.Stat(path + ".1"); err != nil || fi.Size() != int64(len(big)) {
		t.Fatalf("old log not kept as .1: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("live log still present after rotation: %v", err)
	}
}

func TestAuditNilIsNoOp(t *testing.T) {
	var a *Audit
	a.Add(AuditEntry{Action: "x"})
	if got := a.Recent(10, time.Time{}); got != nil {
		t.Fatalf("nil Recent = %v, want nil", got)
	}
}

func TestEveryWriteRouteIsAudited(t *testing.T) {
	s := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), "", AuthOptions{})
	for _, rt := range s.routes() {
		if strings.HasPrefix(rt.pattern, "GET ") {
			continue
		}
		if rt.audit == "" {
			t.Errorf("%s changes state but names no audit action", rt.pattern)
		}
		// Begin only parks a secret in memory until it is confirmed; the
		// rules test is a dry run.
		if rt.audit == "-" && rt.pattern != "POST /api/config/validate" && rt.pattern != "POST /api/account/2fa/begin" && rt.pattern != "POST /api/rules/test" {
			t.Errorf("%s is left unaudited; only POST /api/config/validate, POST /api/account/2fa/begin and POST /api/rules/test may be", rt.pattern)
		}
	}
}

func TestAuditedRecordsOnSuccessOnly(t *testing.T) {
	s := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), "", testOpts("admin", testHash(t, "pw"), ""))
	a, _ := NewAudit("")
	s.SetAudit(a)

	ok := s.audited("config_save", func(w http.ResponseWriter, r *http.Request) {
		noteAudit(r, "config.yaml", "a,b", "v3")
		w.WriteHeader(http.StatusNoContent)
	})
	refused := s.audited("config_save", func(w http.ResponseWriter, r *http.Request) {
		noteAudit(r, "config.yaml", "x", "")
		http.Error(w, "nope", http.StatusUnprocessableEntity)
	})
	implicit := s.audited("bots_refresh", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) })

	req := func() *http.Request {
		r := httptest.NewRequest("POST", "/api/config", nil)
		r.RemoteAddr = "192.0.2.9:4000"
		return withUser(r, config.AdminUser{Username: "admin", Role: config.RoleAdmin})
	}
	refused(httptest.NewRecorder(), req())
	if got := a.Recent(10, time.Time{}); len(got) != 0 {
		t.Fatalf("a 422 left %d entries, want none", len(got))
	}
	ok(httptest.NewRecorder(), req())
	got := a.Recent(10, time.Time{})
	if len(got) != 1 {
		t.Fatalf("a 204 left %d entries, want 1", len(got))
	}
	want := AuditEntry{User: "admin", IP: "192.0.2.9", Action: "config_save", Target: "config.yaml", Detail: "a,b", Version: "v3"}
	if e := got[0]; e.Time.IsZero() || e.User != want.User || e.IP != want.IP || e.Action != want.Action ||
		e.Target != want.Target || e.Detail != want.Detail || e.Version != want.Version {
		t.Fatalf("entry = %+v, want %+v", e, want)
	}
	implicit(httptest.NewRecorder(), req())
	if got := a.Recent(10, time.Time{}); len(got) != 2 || got[0].Action != "bots_refresh" {
		t.Fatalf("a handler that never set a status (200) was not recorded: %+v", got)
	}
	noteAudit(req(), "ignored", "", "") // outside an audited route: must not panic
}

func TestAuditWriterFlushes(t *testing.T) {
	s := &Server{}
	var flushable bool
	h := s.audited("restart", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		f, ok := w.(http.Flusher)
		if flushable = ok; ok {
			f.Flush()
		}
	})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("POST", "/api/restart", nil))
	if !flushable {
		t.Fatal("the audited writer does not implement http.Flusher; handleRestart relies on it")
	}
	if !rec.Flushed {
		t.Fatal("Flush did not reach the underlying writer")
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
}

func auditedServer(t *testing.T, cfg, user, hash string) (http.Handler, *Audit) {
	t.Helper()
	s := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), cfg, testOpts(user, hash, ""))
	a, _ := NewAudit("")
	s.SetAudit(a)
	return s.Handler(), a
}

func TestLoginAudited(t *testing.T) {
	h, a := auditedServer(t, filepath.Join(t.TempDir(), "config.yaml"), "admin", testHash(t, "correct horse"))

	postLogin(h, url.Values{"username": {"mallory"}, "password": {"wrong"}}, nil)
	got := a.Recent(10, time.Time{})
	if len(got) != 1 || got[0].Action != "login_failed" || got[0].Target != "mallory" || got[0].IP != "192.0.2.7" {
		t.Fatalf("after a wrong password: %+v, want one login_failed targeting mallory", got)
	}
	postLogin(h, url.Values{"username": {"admin"}, "password": {"correct horse"}}, nil)
	got = a.Recent(10, time.Time{})
	if len(got) != 2 || got[0].Action != "login" || got[0].User != "admin" {
		t.Fatalf("after a good login: %+v, want a login entry for admin", got)
	}
}

func TestLoginRateLimitedNotAudited(t *testing.T) {
	h, a := auditedServer(t, filepath.Join(t.TempDir(), "config.yaml"), "admin", testHash(t, "pw"))
	for i := 0; i < 30; i++ {
		postLogin(h, url.Values{"username": {"admin"}, "password": {"bad"}}, nil)
	}
	if n := len(a.Recent(500, time.Time{})); n < 1 || n > 6 {
		t.Fatalf("30 rapid failures left %d audit entries, want only the few that weren't rate-limited", n)
	}
}

func TestSettingsSaveAuditDetail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte("abuse:\n  rate_limit:\n    rate: 1.0\n    burst: 15\n"), 0600)
	h, a := auditedServer(t, path, "", "")

	r := httptest.NewRequest("POST", "/api/settings", strings.NewReader(`{"values":{"abuse.rate_limit.burst":30}}`))
	r.Header.Set(csrfHeader, "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	got := a.Recent(10, time.Time{})
	if len(got) != 1 || got[0].Action != "settings_save" || got[0].Target != "config.yaml" ||
		!strings.Contains(got[0].Detail, "abuse.rate_limit.burst") {
		t.Fatalf("entries = %+v, want one settings_save naming abuse.rate_limit.burst", got)
	}
}

func TestAuditEndpoint(t *testing.T) {
	h, a := auditedServer(t, filepath.Join(t.TempDir(), "config.yaml"), "", "")
	a.Add(AuditEntry{Time: time.Now().Add(-time.Minute), Action: "restart"})
	a.Add(AuditEntry{Time: time.Now(), Action: "config_save"})

	w := get(h, "/api/audit?n=1", nil)
	var resp struct{ Entries []AuditEntry }
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != 200 {
		t.Fatalf("GET /api/audit = %d %s (%v)", w.Code, w.Body, err)
	}
	if len(resp.Entries) != 1 || resp.Entries[0].Action != "config_save" {
		t.Fatalf("entries = %+v, want the newest one", resp.Entries)
	}
	before := url.QueryEscape(resp.Entries[0].Time.Format(time.RFC3339Nano))
	w = get(h, "/api/audit?before="+before, nil)
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Entries) != 1 || resp.Entries[0].Action != "restart" {
		t.Fatalf("before cursor: %+v, want the older entry", resp.Entries)
	}
	if w := get(h, "/api/audit?before=yesterday", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad cursor = %d, want 400", w.Code)
	}
	if w := get(h, "/api/audit?before="+before+"&n=0", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("n=0 = %d, want 400", w.Code)
	}
}

func TestNewAuditCreatesParentDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data", "audit")
	path := filepath.Join(dir, "audit.jsonl")
	a, err := NewAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	a.Add(AuditEntry{Action: "restart"})
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0700 {
		t.Fatalf("audit dir: mode %v (%v), want it created 0700", fi.Mode().Perm(), err)
	}
	b, err := NewAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Recent(10, time.Time{}); len(got) != 1 || got[0].Action != "restart" {
		t.Fatalf("after reopen: %+v, want the entry written into the new directory", got)
	}
}

func TestSettingsSaveWithNoEditsNotAudited(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte("abuse:\n  rate_limit:\n    burst: 15\n"), 0600)
	h, a := auditedServer(t, path, "", "")

	r := httptest.NewRequest("POST", "/api/settings", strings.NewReader(`{"values":{}}`))
	r.Header.Set(csrfHeader, "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("no-op save: %d %s", w.Code, w.Body)
	}
	if got := a.Recent(10, time.Time{}); len(got) != 0 {
		t.Fatalf("a settings save with no edits left %+v, want no audit entry", got)
	}
}

func TestAuditFailedLoginsDontCrowdOutChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := NewAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	a.Add(AuditEntry{Time: t0, User: "admin", Action: "config_save", Target: "config.yaml", Version: "v1"})
	// 50 addresses taking turns, so no two failures in a row coalesce.
	for i := 0; i < 6000; i++ {
		a.Add(AuditEntry{Time: t0.Add(time.Duration(i+1) * time.Second), IP: fmt.Sprintf("192.0.2.%d", i%50), Action: "login_failed", Target: "admin"})
	}
	hasSave := func(a *Audit) bool {
		for before := (time.Time{}); ; {
			page := a.Recent(auditMaxPage, before)
			if len(page) == 0 {
				return false
			}
			for _, e := range page {
				if e.Action == "config_save" {
					return true
				}
			}
			before = page[len(page)-1].Time
		}
	}
	if !hasSave(a) {
		t.Fatal("config_save no longer returned by Recent after 6000 failed sign-ins")
	}
	if len(a.failed) != auditKeepFailed {
		t.Errorf("held %d failed sign-ins, want the cap of %d", len(a.failed), auditKeepFailed)
	}
	b, err := NewAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if !hasSave(b) {
		t.Fatal("config_save lost across a reopen")
	}
	if len(b.failed) != auditKeepFailed {
		t.Errorf("after reopen held %d failed sign-ins, want %d", len(b.failed), auditKeepFailed)
	}
}

func TestAuditCoalescesFailedLogins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := NewAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		a.Add(AuditEntry{Time: t0.Add(time.Duration(i) * time.Second), IP: "192.0.2.7", Action: "login_failed", Target: "mallory"})
	}
	check := func(when string, a *Audit) {
		t.Helper()
		got := a.Recent(10, time.Time{})
		if len(got) != 1 || got[0].Count != 100 || !got[0].Time.Equal(t0) || got[0].Detail != "" {
			t.Fatalf("%s: %+v, want one entry at the first failure with count 100", when, got)
		}
	}
	check("in memory", a)
	b, err := NewAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	check("after reopen", b)

	// Another name, another address or the window running out each start a
	// new entry.
	tests := []struct {
		name string
		e    AuditEntry
	}{
		{"other name", AuditEntry{Time: t0.Add(101 * time.Second), IP: "192.0.2.7", Target: "admin"}},
		{"other address", AuditEntry{Time: t0.Add(102 * time.Second), IP: "192.0.2.8", Target: "admin"}},
		{"window over", AuditEntry{Time: t0.Add(102*time.Second + auditFailWindow), IP: "192.0.2.8", Target: "admin"}},
	}
	for i, tt := range tests {
		tt.e.Action = "login_failed"
		a.Add(tt.e)
		if got := a.Recent(10, time.Time{}); len(got) != i+2 || got[0].Count != 1 {
			t.Errorf("%s: %d entries, newest %+v; want a new entry with count 1", tt.name, len(got), got[0])
		}
	}
}

func TestAuditRotatesOnAdd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := NewAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	a.Add(AuditEntry{Time: t0, Action: "config_save", Version: "v1"})
	long := strings.Repeat("x", 4<<10)
	const n = 3000 // about 12 MiB of failed sign-ins, each from its own address
	for i := 0; i < n; i++ {
		a.Add(AuditEntry{Time: t0.Add(time.Duration(i+1) * time.Second), IP: fmt.Sprintf("10.0.%d.%d", i/256, i%256), Action: "login_failed", Target: long})
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("no .1 after the log passed 10 MiB: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() > auditMaxFileBytes {
		t.Fatalf("live log after rotation: %v, %v", fi, err)
	}
	b, err := NewAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.entries) != 1 || b.entries[0].Version != "v1" {
		t.Fatalf("after reopen held changes %+v, want the config_save carried into the new file", b.entries)
	}
	if got := b.Recent(1, time.Time{}); len(got) != 1 || !got[0].Time.Equal(t0.Add(n*time.Second)) {
		t.Fatalf("newest entry after reopen = %+v, want the last one added", got)
	}
}

func TestAuditSkipsOverlongLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	raw := `{"t":"2026-10-01T12:00:00Z","action":"one"}` + "\n" +
		`{"t":"2026-10-01T12:00:01Z","action":"` + strings.Repeat("x", 2<<20) + `"}` + "\n" +
		`{"t":"2026-10-01T12:00:02Z","action":"three"}` + "\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := NewAudit(path)
	if err != nil {
		t.Fatalf("NewAudit with a 2 MiB line: %v", err)
	}
	got := a.Recent(10, time.Time{})
	if len(got) != 2 || got[0].Action != "three" || got[1].Action != "one" {
		t.Fatalf("Recent = %+v, want three and one with the long line skipped", got)
	}
}
