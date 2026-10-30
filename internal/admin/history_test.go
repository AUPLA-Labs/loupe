package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/bots"
	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
)

const (
	cfgA   = "listen: \":8080\"\ncookie_ttl: 86400\n"
	cfgB   = "listen: \":8080\"\ncookie_ttl: 43200\n"
	cfgBad = "listen: \":8080\"\ncookie_ttl: not-a-number\n"
)

// historyServer is a versionedServer over a config.yaml holding contents.
func historyServer(t *testing.T, contents string) (h http.Handler, srv *Server, hist *config.History, a *Audit, path string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	h, srv, hist, a = versionedServer(t, path)
	return
}

func saveConfig(t *testing.T, h http.Handler, body string) {
	t.Helper()
	if w := postJSON(h, "/api/config", body); w.Code != http.StatusNoContent {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
}

func decode(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", w.Body, err)
	}
}

func TestHistoryListMarksCurrent(t *testing.T) {
	h, _, hist, _, path := historyServer(t, cfgA)
	saveConfig(t, h, cfgB)
	newest, _ := hist.List("config")
	if len(newest) != 1 {
		t.Fatalf("versions = %v, want the one saved", newest)
	}

	var resp struct {
		Versions []config.Version `json:"versions"`
		Current  string           `json:"current"`
	}
	w := get(h, "/api/history?file=config", nil)
	if w.Code != 200 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	decode(t, w, &resp)
	if len(resp.Versions) != 1 || resp.Current != newest[0].ID {
		t.Fatalf("list = %+v, want current == newest id %q", resp, newest[0].ID)
	}

	os.WriteFile(path, []byte(cfgA), 0600) // a hand edit the dashboard never saw
	resp.Current = "x"
	decode(t, get(h, "/api/history?file=config", nil), &resp)
	if resp.Current != "" {
		t.Fatalf("current = %q after a hand edit, want \"\"", resp.Current)
	}
}

func TestHistoryDiffAgainstCurrent(t *testing.T) {
	h, _, hist, _, path := historyServer(t, cfgA)
	saveConfig(t, h, cfgB)
	vs, _ := hist.List("config")
	os.WriteFile(path, []byte(cfgA+"extra: 1\n"), 0600)

	w := get(h, "/api/history/diff?file=config&from="+vs[0].ID+"&to=current", nil)
	if w.Code != 200 {
		t.Fatalf("diff: %d %s", w.Code, w.Body)
	}
	var resp struct {
		Lines   []config.DiffLine `json:"lines"`
		Added   int               `json:"added"`
		Removed int               `json:"removed"`
	}
	decode(t, w, &resp)
	wantLines := config.LineDiff([]byte(cfgB), []byte(cfgA+"extra: 1\n"))
	added, removed := config.DiffStat(wantLines)
	if resp.Added != added || resp.Removed != removed || len(resp.Lines) != len(wantLines) {
		t.Fatalf("diff = %+v, want %d added, %d removed over %d lines", resp, added, removed, len(wantLines))
	}
	if added == 0 || removed == 0 {
		t.Fatalf("test data should differ both ways, got +%d -%d", added, removed)
	}
}

func TestRestoreConfig(t *testing.T) {
	h, _, hist, a, path := historyServer(t, cfgA)
	saveConfig(t, h, cfgA+"# a\n")
	saveConfig(t, h, cfgB)
	vs, _ := hist.List("config")
	if len(vs) != 2 {
		t.Fatalf("versions = %v, want 2", vs)
	}
	older := vs[1].ID // newest first
	oldBytes, _ := hist.Get("config", older)

	w := postJSON(h, "/api/history/restore", `{"file":"config","version":"`+older+`"}`)
	if w.Code != 200 {
		t.Fatalf("restore: %d %s", w.Code, w.Body)
	}
	if got, _ := os.ReadFile(path); string(got) != string(oldBytes) {
		t.Fatalf("config.yaml = %q, want the restored %q", got, oldBytes)
	}
	var resp struct {
		ETag    string `json:"etag"`
		Version string `json:"version"`
		Restart bool   `json:"restart"`
	}
	decode(t, w, &resp)
	after, _ := hist.List("config")
	if len(after) != 3 || resp.Version != after[0].ID || resp.Version == older {
		t.Fatalf("response %+v, versions %v, want a new version appended", resp, after)
	}
	if !resp.Restart || resp.ETag != configETag(oldBytes) {
		t.Fatalf("response %+v, want restart and the etag of the restored bytes", resp)
	}
	entries := a.Recent(10, time.Time{})
	last := entries[0]
	if last.Action != "history_restore" || last.Target != "config.yaml" || last.Detail != "restored "+older || last.Version != resp.Version {
		t.Fatalf("audit entry = %+v, want history_restore of config.yaml, restored %s, version %s", last, older, resp.Version)
	}
}

func TestRestoreRejectsInvalidConfig(t *testing.T) {
	h, _, hist, a, path := historyServer(t, cfgA)
	id, err := hist.Save("config", []byte(cfgBad))
	if err != nil {
		t.Fatal(err)
	}
	w := postJSON(h, "/api/history/restore", `{"file":"config","version":"`+id+`"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("restore of an invalid version: %d %s, want 422", w.Code, w.Body)
	}
	if got, _ := os.ReadFile(path); string(got) != cfgA {
		t.Fatalf("config.yaml = %q, want it unchanged", got)
	}
	if n := len(a.Recent(10, time.Time{})); n != 0 {
		t.Fatalf("%d audit entries for a refused restore, want none", n)
	}
}

func TestRestoreRejectsCheckOrderingConfig(t *testing.T) {
	h, _, hist, a, path := historyServer(t, cfgA)
	// Valid on its own, but the request burst is below the page burst.
	bad := cfgA + "abuse:\n  clearance_budget:\n    doc_burst: 500\n    all_burst: 200\n"
	if _, err := config.LoadBytes([]byte(bad)); err != nil {
		t.Fatalf("the planted version should pass LoadBytes: %v", err)
	}
	id, err := hist.Save("config", []byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	w := postJSON(h, "/api/history/restore", `{"file":"config","version":"`+id+`"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("restore of a mis-ordered version: %d %s, want 422", w.Code, w.Body)
	}
	if got, _ := os.ReadFile(path); string(got) != cfgA {
		t.Fatalf("config.yaml = %q, want it unchanged", got)
	}
	if n := len(a.Recent(10, time.Time{})); n != 0 {
		t.Fatalf("%d audit entries for a refused restore, want none", n)
	}
}

func TestRestoreETagConflict(t *testing.T) {
	h, _, hist, _, path := historyServer(t, cfgA)
	saveConfig(t, h, cfgB)
	vs, _ := hist.List("config")

	w := postJSON(h, "/api/history/restore", `{"file":"config","version":"`+vs[0].ID+`","etag":"\"stale\""}`)
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("restore with a stale etag: %d %s, want 412", w.Code, w.Body)
	}
	if got, _ := os.ReadFile(path); string(got) != cfgB {
		t.Fatalf("config.yaml = %q, want it unchanged", got)
	}
}

func TestRestoreBotsValidates(t *testing.T) {
	dir := t.TempDir()
	m, err := bots.New(bots.Options{PolicyFile: filepath.Join(dir, "bots.yaml"), RangesDir: filepath.Join(dir, "ranges")})
	if err != nil {
		t.Fatal(err)
	}
	h, srv, hist, a := versionedServer(t, filepath.Join(dir, "config.yaml"))
	srv.SetBots(m)
	m.SetOnPolicyWritten(func(b []byte) { hist.Save("bots", b) })

	bad, err := hist.Save("bots", []byte("categories:\n  preview: explode\n"))
	if err != nil {
		t.Fatal(err)
	}
	if w := postJSON(h, "/api/history/restore", `{"file":"bots","version":"`+bad+`"}`); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("restore of a bad policy: %d %s, want 422", w.Code, w.Body)
	}

	good, err := hist.Save("bots", []byte("categories:\n  preview: block\n"))
	if err != nil {
		t.Fatal(err)
	}
	w := postJSON(h, "/api/history/restore", `{"file":"bots","version":"`+good+`"}`)
	if w.Code != 200 {
		t.Fatalf("restore: %d %s", w.Code, w.Body)
	}
	if got := m.Policy().Categories["preview"]; got != "block" {
		t.Fatalf("live policy preview = %q, want block", got)
	}
	var resp map[string]any
	decode(t, w, &resp)
	vs, _ := hist.List("bots")
	if resp["version"] != vs[0].ID || resp["restart"] != nil {
		t.Fatalf("response %v, want version %s and no restart", resp, vs[0].ID)
	}
	entries := a.Recent(10, time.Time{})
	if len(entries) != 1 || entries[0].Action != "history_restore" || entries[0].Target != "bots.yaml" ||
		entries[0].Detail != "restored "+good || entries[0].Version != vs[0].ID {
		t.Fatalf("audit entries = %+v, want one history_restore of bots.yaml linking %s", entries, vs[0].ID)
	}
}

func TestHistoryBadParams(t *testing.T) {
	h, _, hist, _, _ := historyServer(t, cfgA)
	id, err := hist.Save("config", []byte(cfgB))
	if err != nil {
		t.Fatal(err)
	}
	unknown := "20000101T000000.000Z-deadbeef"
	tests := []struct {
		name, method, path, body string
		want                     int
	}{
		{"list unknown file", "GET", "/api/history?file=passwd", "", 400},
		{"list no file", "GET", "/api/history", "", 400},
		{"diff unknown file", "GET", "/api/history/diff?file=passwd&from=" + id + "&to=current", "", 400},
		{"diff malformed from", "GET", "/api/history/diff?file=config&from=..%2Fx&to=current", "", 400},
		{"diff malformed to", "GET", "/api/history/diff?file=config&from=" + id + "&to=..%2Fx", "", 400},
		{"diff unknown from", "GET", "/api/history/diff?file=config&from=" + unknown + "&to=current", "", 404},
		{"diff unknown to", "GET", "/api/history/diff?file=config&from=" + id + "&to=" + unknown, "", 404},
		{"restore unknown file", "POST", "/api/history/restore", `{"file":"passwd","version":"` + id + `"}`, 400},
		{"restore malformed id", "POST", "/api/history/restore", `{"file":"config","version":"../x"}`, 400},
		{"restore unknown id", "POST", "/api/history/restore", `{"file":"config","version":"` + unknown + `"}`, 404},
		{"restore bad body", "POST", "/api/history/restore", `{`, 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var w *httptest.ResponseRecorder
			if tt.method == "GET" {
				w = get(h, tt.path, nil)
			} else {
				w = postJSON(h, tt.path, tt.body)
			}
			if w.Code != tt.want {
				t.Fatalf("%s %s: %d %s, want %d", tt.method, tt.path, w.Code, w.Body, tt.want)
			}
		})
	}
}

// A restore must not discard an edit made outside the dashboard: the bytes on
// disk become a version first.
func TestRestoreKeepsHandEditedConfig(t *testing.T) {
	h, _, hist, _, path := historyServer(t, cfgA)
	saveConfig(t, h, cfgB)
	vs, _ := hist.List("config")
	older := vs[0].ID
	hand := cfgA + "# edited by hand\n"
	os.WriteFile(path, []byte(hand), 0600)

	if w := postJSON(h, "/api/history/restore", `{"file":"config","version":"`+older+`"}`); w.Code != 200 {
		t.Fatalf("restore: %d %s", w.Code, w.Body)
	}
	if got, _ := os.ReadFile(path); string(got) != cfgB {
		t.Fatalf("config.yaml = %q, want the restored %q", got, cfgB)
	}
	all, _ := hist.List("config")
	found := false
	for _, v := range all {
		if b, _ := hist.Get("config", v.ID); string(b) == hand {
			found = true
		}
	}
	if !found {
		t.Fatalf("hand-edited bytes are in none of %v", all)
	}
}

func TestRestoreKeepsHandEditedBots(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "bots.yaml")
	m, err := bots.New(bots.Options{PolicyFile: policy, RangesDir: filepath.Join(dir, "ranges")})
	if err != nil {
		t.Fatal(err)
	}
	h, srv, hist, _ := versionedServer(t, filepath.Join(dir, "config.yaml"))
	srv.SetBots(m)
	m.SetOnPolicyWritten(func(b []byte) { hist.Save("bots", b) })
	good, err := hist.Save("bots", []byte("categories:\n  preview: block\n"))
	if err != nil {
		t.Fatal(err)
	}
	hand := "categories:\n  seo: block\n"
	if err := os.WriteFile(policy, []byte(hand), 0600); err != nil {
		t.Fatal(err)
	}

	if w := postJSON(h, "/api/history/restore", `{"file":"bots","version":"`+good+`"}`); w.Code != 200 {
		t.Fatalf("restore: %d %s", w.Code, w.Body)
	}
	all, _ := hist.List("bots")
	found := false
	for _, v := range all {
		if b, _ := hist.Get("bots", v.ID); string(b) == hand {
			found = true
		}
	}
	if !found {
		t.Fatalf("hand-edited policy is in none of %v", all)
	}
}

// If the current file can't be put in the history, nothing is restored.
func TestRestoreRefusedWhenHistoryUnwritable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(cfgA), 0600)
	histDir := filepath.Join(t.TempDir(), "history")
	hist := config.NewHistory(histDir, 10)
	srv := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), path, AuthOptions{})
	a, _ := NewAudit("")
	srv.SetHistory(hist)
	srv.SetAudit(a)
	h := srv.Handler()
	saveConfig(t, h, cfgB)
	vs, _ := hist.List("config")
	hand := cfgA + "# edited by hand\n"
	os.WriteFile(path, []byte(hand), 0600)
	cdir := filepath.Join(histDir, "config") // read-only: no new version can be written
	if err := os.Chmod(cdir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(cdir, 0700)

	w := postJSON(h, "/api/history/restore", `{"file":"config","version":"`+vs[0].ID+`"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("restore with unwritable history: %d %s, want 500", w.Code, w.Body)
	}
	if got, _ := os.ReadFile(path); string(got) != hand {
		t.Fatalf("config.yaml = %q, want it unchanged", got)
	}
	if n := len(a.Recent(10, time.Time{})); n != 1 { // only the earlier save
		t.Fatalf("%d audit entries, want only the earlier save", n)
	}
}

func TestHistoryDiffFromCurrent(t *testing.T) {
	h, _, hist, _, path := historyServer(t, cfgA)
	saveConfig(t, h, cfgB)
	vs, _ := hist.List("config")
	hand := cfgA + "extra: 1\n"
	os.WriteFile(path, []byte(hand), 0600)

	w := get(h, "/api/history/diff?file=config&from=current&to="+vs[0].ID, nil)
	if w.Code != 200 {
		t.Fatalf("diff: %d %s", w.Code, w.Body)
	}
	var resp struct {
		Lines []config.DiffLine `json:"lines"`
	}
	decode(t, w, &resp)
	want := config.LineDiff([]byte(hand), []byte(cfgB))
	if len(resp.Lines) != len(want) {
		t.Fatalf("diff has %d lines, want %d", len(resp.Lines), len(want))
	}
}
