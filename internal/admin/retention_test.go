package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func logLine(t time.Time, ip string) string {
	return fmt.Sprintf(`{"t":%q,"action":"ALLOW","ip":%q}`, t.Format(time.RFC3339Nano), ip) + "\n"
}

func TestAgedStorePrunesLogOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	now := time.Now()
	// Out of order on purpose: summary events can be logged after newer ones.
	src := logLine(now.Add(-72*time.Hour), "1.1.1.1") + logLine(now.Add(-time.Hour), "2.2.2.2") +
		logLine(now.Add(-50*time.Hour), "3.3.3.3") + "not json\n" + logLine(now.Add(-time.Minute), "4.4.4.4")
	os.WriteFile(path, []byte(src), 0o644)

	s, err := OpenStore(StoreOptions{MaxAge: 48 * time.Hour, LogPath: path, PruneLog: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var ips []string
	for _, e := range s.Recent(0, "") {
		ips = append(ips, e.IP)
	}
	if strings.Join(ips, " ") != "2.2.2.2 4.4.4.4" {
		t.Fatalf("in memory: %v", ips)
	}
	b, _ := os.ReadFile(path)
	if want := logLine(now.Add(-time.Hour), "2.2.2.2") + logLine(now.Add(-time.Minute), "4.4.4.4"); string(b) != want {
		t.Fatalf("log file:\n%s\nwant:\n%s", b, want)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v, want the original 0644", fi.Mode().Perm())
	}
}

func TestAgedStoreLeavesFreshLogAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	src := logLine(time.Now().Add(-time.Hour), "1.1.1.1")
	os.WriteFile(path, []byte(src), 0o644)
	before, _ := os.Stat(path)
	s, err := OpenStore(StoreOptions{MaxAge: 48 * time.Hour, LogPath: path, PruneLog: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Error("the log was rewritten although nothing in it had expired")
	}
}

func TestAgedStorePrunesAsTimePasses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	s, err := OpenStore(StoreOptions{MaxAge: time.Hour, LogPath: path, PruneLog: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t0 := time.Now()
	s.Add(Event{Time: t0, IP: "1.1.1.1"})
	s.Add(Event{Time: t0.Add(40 * time.Minute), IP: "2.2.2.2"})

	s.prune(t0.Add(90 * time.Minute))
	if got := s.Recent(0, ""); len(got) != 1 || got[0].IP != "2.2.2.2" {
		t.Fatalf("after prune: %+v", got)
	}
	// Writes after the rewrite land in the new file.
	s.Add(Event{Time: t0.Add(95 * time.Minute), IP: "3.3.3.3"})
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "1.1.1.1") || !strings.Contains(string(b), "2.2.2.2") || !strings.Contains(string(b), "3.3.3.3") {
		t.Fatalf("log file after prune:\n%s", b)
	}
}

func TestAgedStoreGrowsToCeiling(t *testing.T) {
	defer func(n int) { agedCeiling = n }(agedCeiling)
	agedCeiling = 5000
	s, err := OpenStore(StoreOptions{MaxAge: time.Hour, PruneLog: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	t0 := time.Now()
	for i := 0; i < 6000; i++ {
		s.Add(Event{Time: t0.Add(time.Duration(i) * time.Millisecond), Score: i})
	}
	got := s.Recent(0, "")
	if len(got) != 5000 || got[0].Score != 1000 || got[4999].Score != 5999 {
		t.Fatalf("kept %d events, %d..%d", len(got), got[0].Score, got[len(got)-1].Score)
	}
	if b := s.Buffer(); b.Size != 5000 || b.Capacity != 5000 || b.MaxAge != 3600 {
		t.Fatalf("buffer = %+v", b)
	}
}

func TestCountStoreKeepsWholeLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	src := logLine(time.Now().Add(-1000*time.Hour), "1.1.1.1")
	os.WriteFile(path, []byte(src), 0o644)
	s, err := NewStore(10, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.Recent(0, "")) != 1 || s.Buffer().MaxAge != 0 {
		t.Fatal("an event-count store dropped an old event")
	}
}

func TestAgedStoreCanKeepWholeLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	now := time.Now()
	src := logLine(now.Add(-72*time.Hour), "1.1.1.1") + logLine(now.Add(-time.Minute), "2.2.2.2")
	os.WriteFile(path, []byte(src), 0o644)
	s, err := OpenStore(StoreOptions{MaxAge: 48 * time.Hour, LogPath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := s.Recent(0, ""); len(got) != 1 || got[0].IP != "2.2.2.2" {
		t.Fatalf("in memory: %+v", got)
	}
	s.prune(now.Add(time.Hour))
	if b, _ := os.ReadFile(path); string(b) != src {
		t.Fatalf("the log was pruned although prune_log is off:\n%s", b)
	}
}

func TestCountStorePrunesLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	t0 := time.Now().Add(-time.Hour)
	var src string
	for i := 0; i < 5; i++ {
		src += logLine(t0.Add(time.Duration(i)*time.Second), fmt.Sprintf("1.1.1.%d", i))
	}
	os.WriteFile(path, []byte(src+"not json\n"), 0o644)
	s, err := OpenStore(StoreOptions{Capacity: 3, LogPath: path, PruneLog: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if b, _ := os.ReadFile(path); strings.Count(string(b), "\n") != 3 || !strings.HasPrefix(string(b), logLine(t0.Add(2*time.Second), "1.1.1.2")) {
		t.Fatalf("log after open:\n%s", b)
	}
	// The log may run over between prunes; the next one trims it back.
	s.Add(Event{IP: "2.2.2.2"})
	s.Add(Event{IP: "3.3.3.3"})
	s.prune(time.Now())
	b, _ := os.ReadFile(path)
	if strings.Count(string(b), "\n") != 3 || !strings.Contains(string(b), "1.1.1.4") || !strings.Contains(string(b), "3.3.3.3") {
		t.Fatalf("log after prune:\n%s", b)
	}
	if got := s.Recent(0, ""); len(got) != 3 || got[0].IP != "1.1.1.4" {
		t.Fatalf("in memory: %+v", got)
	}
}

func TestSettingsSaveRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	src := "admin:\n  capacity: 20000  # in-memory ring buffer size\n"
	os.WriteFile(path, []byte(src), 0600)
	h := NewServer(newTestStore(t, 10), nil, path, AuthOptions{}).Handler()
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/settings", strings.NewReader(body))
		r.Header.Set(csrfHeader, "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := post(`{"values":{"admin.retention":"age","admin.max_age_days":7,"admin.prune_log":false}}`); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "retention: age") || !strings.Contains(string(got), "max_age_days: 7  # 7 days") || !strings.Contains(string(got), "prune_log: false") {
		t.Fatalf("file:\n%s", got)
	}
	for _, body := range []string{
		`{"values":{"admin.retention":"forever"}}`,
		`{"values":{"admin.retention":true}}`,
		`{"values":{"admin.max_age_days":0}}`,
	} {
		if w := post(body); w.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: got %d, want 422", body, w.Code)
		}
	}
}
