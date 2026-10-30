package rules

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const goodRulesYAML = `rules:
  - id: block-bad
    mode: enforce
    action: block
    match:
      paths: [{prefix: /admin}]
`

const otherRulesYAML = `rules:
  - id: block-other
    mode: enforce
    action: block
    match:
      paths: [{prefix: /other}]
  - id: second
    action: log
    match:
      paths: [{prefix: /x}]
`

func writeRules(t *testing.T, path, content string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// hitID evaluates a GET for urlPath from a public address and returns the
// enforced rule's ID ("" for no hit).
func hitID(s *Set, urlPath string) string {
	r := httptest.NewRequest("GET", urlPath, nil)
	h, _ := s.Evaluate(&Facts{Req: r, IP: net.ParseIP("198.51.100.7"), ClientKey: "k"})
	if h == nil {
		return ""
	}
	return h.ID
}

func TestManagerMissingFileIsEmpty(t *testing.T) {
	m := NewManager(filepath.Join(t.TempDir(), "rules.yaml"))
	if n := m.Set().Len(); n != 0 {
		t.Fatalf("Set().Len() = %d, want 0 for a missing file", n)
	}
	if e := m.LoadErr(); e != "" {
		t.Fatalf("LoadErr() = %q, want empty for a missing file", e)
	}
	if len(m.Rules()) != 0 {
		t.Fatalf("Rules() = %v, want none", m.Rules())
	}
}

func TestManagerLoadsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRules(t, path, goodRulesYAML, time.Now())
	m := NewManager(path)
	if m.LoadErr() != "" {
		t.Fatalf("LoadErr() = %q", m.LoadErr())
	}
	if m.Path() != path {
		t.Fatalf("Path() = %q, want %q", m.Path(), path)
	}
	if got := hitID(m.Set(), "/admin/x"); got != "block-bad" {
		t.Fatalf("hit = %q, want block-bad", got)
	}
	if rs := m.Rules(); len(rs) != 1 || rs[0].ID != "block-bad" {
		t.Fatalf("Rules() = %+v", rs)
	}
}

func TestManagerReloadsChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	writeRules(t, path, goodRulesYAML, t0)
	m := NewManager(path)

	m.reloadIfChanged()
	if got := hitID(m.Set(), "/admin"); got != "block-bad" {
		t.Fatalf("unchanged file: hit = %q", got)
	}

	writeRules(t, path, otherRulesYAML, t0.Add(time.Minute))
	m.reloadIfChanged()
	if got := hitID(m.Set(), "/other"); got != "block-other" {
		t.Fatalf("after reload: hit = %q, want block-other", got)
	}
	if got := hitID(m.Set(), "/admin"); got != "" {
		t.Fatalf("old rule still in force: %q", got)
	}
	if m.Set().Len() != 2 || len(m.Rules()) != 2 {
		t.Fatalf("Len = %d, Rules = %d, want 2", m.Set().Len(), len(m.Rules()))
	}
}

func TestManagerReloadsSameMtimeDifferentSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	writeRules(t, path, goodRulesYAML, t0)
	m := NewManager(path)
	writeRules(t, path, otherRulesYAML, t0) // coarse mtime: only the size differs
	m.reloadIfChanged()
	if got := hitID(m.Set(), "/other"); got != "block-other" {
		t.Fatalf("hit = %q, want block-other", got)
	}
}

func TestManagerPicksUpFileCreatedLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	m := NewManager(path)
	writeRules(t, path, goodRulesYAML, time.Now())
	m.reloadIfChanged()
	if got := hitID(m.Set(), "/admin"); got != "block-bad" {
		t.Fatalf("hit = %q, want block-bad", got)
	}
}

func TestManagerKeepsLastGoodSetOnBadFile(t *testing.T) {
	bad := []struct {
		name, yaml string
		wantInErr  []string
	}{
		{"bad cidr", "rules:\n  - id: typo\n    action: block\n    match:\n      ips: [10.0.0.0/33]\n", []string{"typo", "ips"}},
		{"bad regex", "rules:\n  - id: typo\n    action: block\n    match:\n      paths: [{regex: \"(\"}]\n", []string{"typo", "regex"}},
		{"unknown tier", "rules:\n  - id: typo\n    action: challenge\n    tier: nonsense\n    match:\n      paths: [{prefix: /}]\n", []string{"typo", "tier"}},
		{"duplicate id", "rules:\n  - id: typo\n    action: block\n    match:\n      paths: [{prefix: /a}]\n  - id: typo\n    action: block\n    match:\n      paths: [{prefix: /b}]\n", []string{"typo", "duplicate"}},
		{"broken yaml", "rules:\n  - id: [unclosed\n", nil},
		{"unknown key", "rules:\n  - id: typo\n    acton: block\n    match:\n      paths: [{prefix: /}]\n", []string{"acton"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.yaml")
			t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
			writeRules(t, path, goodRulesYAML, t0)
			var logs []string
			m := NewManager(path)
			m.logf = func(format string, args ...any) { logs = append(logs, format) }
			before := m.Set()

			writeRules(t, path, tc.yaml, t0.Add(time.Minute))
			m.reloadIfChanged()

			if got := hitID(m.Set(), "/admin"); got != "block-bad" {
				t.Fatalf("previous rule no longer in force: hit = %q", got)
			}
			if m.Set() != before {
				t.Error("Set() was replaced by a bad file")
			}
			if rs := m.Rules(); len(rs) != 1 || rs[0].ID != "block-bad" {
				t.Fatalf("Rules() = %+v, want the previous rules", rs)
			}
			e := m.LoadErr()
			if !strings.HasPrefix(e, path+": ") {
				t.Fatalf("LoadErr() = %q, want it to start with the path", e)
			}
			for _, w := range tc.wantInErr {
				if !strings.Contains(e, w) {
					t.Errorf("LoadErr() = %q, want it to mention %q", e, w)
				}
			}
			if len(logs) != 1 {
				t.Errorf("logged %d times, want 1", len(logs))
			}

			// The same broken file with a new mtime is not logged again.
			writeRules(t, path, tc.yaml, t0.Add(2*time.Minute))
			m.reloadIfChanged()
			if len(logs) != 1 {
				t.Errorf("same error logged %d times, want once", len(logs))
			}
			if m.LoadErr() != e {
				t.Errorf("LoadErr() changed to %q", m.LoadErr())
			}

			// Fixing the file clears the error and applies the new set.
			writeRules(t, path, otherRulesYAML, t0.Add(3*time.Minute))
			m.reloadIfChanged()
			if m.LoadErr() != "" {
				t.Fatalf("LoadErr() = %q after the fix, want empty", m.LoadErr())
			}
			if got := hitID(m.Set(), "/other"); got != "block-other" {
				t.Fatalf("fixed file not applied: hit = %q", got)
			}
		})
	}
}

func TestManagerBadFileAtStartupIsEmptyWithError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRules(t, path, "rules: [", time.Now())
	m := NewManager(path)
	if m.Set().Len() != 0 {
		t.Fatalf("Len = %d, want an empty set", m.Set().Len())
	}
	if !strings.HasPrefix(m.LoadErr(), path+": ") {
		t.Fatalf("LoadErr() = %q", m.LoadErr())
	}
}

func TestManagerLoadErrCountsMoreErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRules(t, path, "rules:\n  - id: a\n    action: bogus\n    match:\n      ips: [nope]\n  - id: b\n    action: bogus\n    match:\n      ips: [nope]\n", time.Now())
	m := NewManager(path)
	if !strings.Contains(m.LoadErr(), "; and ") || !strings.HasSuffix(m.LoadErr(), " more") {
		t.Fatalf("LoadErr() = %q, want a trailing '; and N more'", m.LoadErr())
	}
}

func TestSavePrunesExpiredRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	m := NewManager(path)
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	rs := []Rule{
		enforce("expired", Match{Paths: []PathMatch{{Prefix: "/a"}}}),
		enforce("at-now", Match{Paths: []PathMatch{{Prefix: "/b"}}}),
		enforce("live", Match{Paths: []PathMatch{{Prefix: "/c"}}}),
		enforce("forever", Match{Paths: []PathMatch{{Prefix: "/d"}}}),
	}
	rs[0].Expires, rs[1].Expires, rs[2].Expires = &past, &now, &future
	if err := m.Save(rs); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got := m.Rules()
	if len(got) != 2 || got[0].ID != "live" || got[1].ID != "forever" {
		t.Fatalf("Rules() = %+v, want live and forever", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := Parse(data)
	if err != nil || len(disk) != 2 {
		t.Fatalf("file holds %d rules (err %v), want 2:\n%s", len(disk), err, data)
	}
	if !disk[0].Expires.Equal(future) {
		t.Errorf("expires round-tripped as %v, want %v", disk[0].Expires, future)
	}
	if m.Set().Len() != 2 {
		t.Errorf("Set().Len() = %d, want 2", m.Set().Len())
	}
}

func TestSaveRejectsInvalidAndWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRules(t, path, goodRulesYAML, time.Now().Add(-time.Hour))
	m := NewManager(path)
	before, _ := os.ReadFile(path)

	bad := []Rule{
		enforce("one", Match{IPs: []string{"10.0.0.0/33"}}),
		enforce("two", Match{Paths: []PathMatch{{Regex: "("}}}),
	}
	err := m.Save(bad)
	if err == nil {
		t.Fatal("Save accepted invalid rules")
	}
	var re *RuleError
	if !errors.As(err, &re) {
		t.Errorf("error %v does not wrap a *RuleError", err)
	}
	if !strings.Contains(err.Error(), "one") || !strings.Contains(err.Error(), "two") {
		t.Errorf("error %q should name every bad rule", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Errorf("file changed:\n%s", after)
	}
	if got := hitID(m.Set(), "/admin"); got != "block-bad" {
		t.Errorf("live set changed after a rejected save: hit = %q", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("directory holds %d entries, want only rules.yaml", len(entries))
	}
}

func TestSaveWritesPrivateFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data", "nested")
	path := filepath.Join(dir, "rules.yaml")
	m := NewManager(path)
	yes := true
	r := enforce("r1", Match{Paths: []PathMatch{{Prefix: "/x"}}, Datacenter: &yes})
	r.Name = "R one"
	if err := m.Save([]Rule{r}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", di.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	rs, err := Parse(data)
	if err != nil || len(rs) != 1 || rs[0].ID != "r1" || rs[0].Name != "R one" || rs[0].Match.Datacenter == nil || !*rs[0].Match.Datacenter {
		t.Fatalf("round trip failed: %+v, %v\n%s", rs, err, data)
	}
	// The save is not mistaken for an external edit: nothing is reloaded or logged.
	var logs int
	m.logf = func(string, ...any) { logs++ }
	m.reloadIfChanged()
	if logs != 0 || m.LoadErr() != "" {
		t.Errorf("reload after save logged %d lines, LoadErr %q", logs, m.LoadErr())
	}
}

func TestSaveEmptyWritesEmptyList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRules(t, path, goodRulesYAML, time.Now().Add(-time.Hour))
	m := NewManager(path)
	if err := m.Save(nil); err != nil {
		t.Fatalf("Save(nil): %v", err)
	}
	data, _ := os.ReadFile(path)
	if strings.TrimSpace(string(data)) != "rules: []" {
		t.Fatalf("file = %q, want \"rules: []\"", data)
	}
	if m.Set().Len() != 0 {
		t.Errorf("Len = %d, want 0", m.Set().Len())
	}
}

func TestSaveClearsLoadErr(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRules(t, path, "rules: [", time.Now())
	m := NewManager(path)
	if m.LoadErr() == "" {
		t.Fatal("expected a load error")
	}
	if err := m.Save([]Rule{enforce("ok", Match{Paths: []PathMatch{{Prefix: "/"}}})}); err != nil {
		t.Fatal(err)
	}
	if m.LoadErr() != "" {
		t.Errorf("LoadErr() = %q after a good save", m.LoadErr())
	}
}

func TestRulesReturnsDeepCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRules(t, path, "rules:\n  - id: a\n    action: block\n    mode: enforce\n    match:\n      paths: [{prefix: /a}]\n    except:\n      ips: [10.0.0.1]\n", time.Now())
	m := NewManager(path)
	rs := m.Rules()
	rs[0].ID = "mutated"
	rs[0].Match.Paths[0].Prefix = "/mutated"
	rs[0].Except.IPs[0] = "1.2.3.4"
	rs[0].Except.IPs = append(rs[0].Except.IPs, "5.6.7.8")
	again := m.Rules()
	if again[0].ID != "a" || again[0].Match.Paths[0].Prefix != "/a" || again[0].Except.IPs[0] != "10.0.0.1" || len(again[0].Except.IPs) != 1 {
		t.Fatalf("live rules were mutated through Rules(): %+v", again[0])
	}
}

func TestSaveDoesNotAliasCallersRules(t *testing.T) {
	m := NewManager(filepath.Join(t.TempDir(), "rules.yaml"))
	in := []Rule{enforce("a", Match{Paths: []PathMatch{{Prefix: "/a"}}})}
	if err := m.Save(in); err != nil {
		t.Fatal(err)
	}
	in[0].Match.Paths[0].Prefix = "/mutated"
	if got := m.Rules()[0].Match.Paths[0].Prefix; got != "/a" {
		t.Fatalf("caller's later edit leaked into the live rules: %q", got)
	}
}

func TestManagerRunReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	m := NewManager(path)
	m.every = 10 * time.Millisecond
	ctx := t.Context()
	m.logf = func(string, ...any) {}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Run did not return after its context ended")
		}
	}()
	writeRules(t, path, goodRulesYAML, time.Now())
	deadline := time.Now().Add(2 * time.Second)
	for hitID(m.Set(), "/admin") == "" {
		if time.Now().After(deadline) {
			t.Fatal("Run never picked up the file")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestManagerIgnoresEmptyFileAfterLoad(t *testing.T) {
	for _, empty := range []string{"", "  \n\t\n"} {
		path := filepath.Join(t.TempDir(), "rules.yaml")
		t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
		writeRules(t, path, goodRulesYAML, t0)
		var logs []string
		m := NewManager(path)
		m.logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }

		writeRules(t, path, empty, t0.Add(time.Minute))
		m.reloadIfChanged()
		m.reloadIfChanged()
		if got := hitID(m.Set(), "/admin"); got != "block-bad" {
			t.Fatalf("empty file %q dropped the rules: hit = %q", empty, got)
		}
		if m.LoadErr() != "" {
			t.Errorf("LoadErr() = %q, want none while a write may be in progress", m.LoadErr())
		}
		if len(logs) != 1 || !strings.Contains(logs[0], "is empty; keeping the current rules") {
			t.Errorf("logs = %q, want one 'empty' notice", logs)
		}

		// The write finishes: the content is picked up, since nothing was recorded as seen.
		writeRules(t, path, otherRulesYAML, t0.Add(2*time.Minute))
		m.reloadIfChanged()
		if got := hitID(m.Set(), "/other"); got != "block-other" {
			t.Fatalf("completed write not applied: hit = %q", got)
		}

		// An intentional clear still works.
		writeRules(t, path, "rules: []\n", t0.Add(3*time.Minute))
		m.reloadIfChanged()
		if m.Set().Len() != 0 {
			t.Fatalf("rules: [] left %d rules in force", m.Set().Len())
		}
	}
}

func TestManagerEmptyFileOnFreshStartIsEmptySet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRules(t, path, "", time.Now())
	m := NewManager(path)
	if m.Set().Len() != 0 || m.LoadErr() != "" {
		t.Fatalf("Len = %d, LoadErr = %q, want an empty set and no error", m.Set().Len(), m.LoadErr())
	}
}

func TestManagerSkipsFileChangingDuringRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	writeRules(t, path, goodRulesYAML, t0)
	m := NewManager(path)
	m.logf = func(string, ...any) {}

	// A truncated prefix of a valid file, as seen mid-write; the file grows
	// after the read, before the manager looks again.
	half := otherRulesYAML[:len(otherRulesYAML)/2]
	writeRules(t, path, otherRulesYAML, t0.Add(time.Minute))
	m.readFile = func(string) ([]byte, error) {
		if err := os.WriteFile(path, []byte(otherRulesYAML+"\n"), 0o600); err != nil {
			t.Error(err)
		}
		return []byte(half), nil
	}
	m.reloadIfChanged()
	if got := hitID(m.Set(), "/admin"); got != "block-bad" {
		t.Fatalf("a file that changed during the read was applied: hit = %q", got)
	}
	if m.LoadErr() != "" {
		t.Errorf("LoadErr() = %q, want none (retry quietly)", m.LoadErr())
	}

	// Next tick the file is stable and is read in full.
	m.readFile = os.ReadFile
	m.reloadIfChanged()
	if got := hitID(m.Set(), "/other"); got != "block-other" {
		t.Fatalf("stable file not applied on the next tick: hit = %q", got)
	}
}

func TestManagerReportsUnreadableFileAndRecovers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of mode")
	}
	path := filepath.Join(t.TempDir(), "rules.yaml")
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	writeRules(t, path, goodRulesYAML, t0)
	m := NewManager(path)
	var logs int
	m.logf = func(string, ...any) { logs++ }

	writeRules(t, path, otherRulesYAML, t0.Add(time.Minute))
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	m.reloadIfChanged()
	m.reloadIfChanged()
	if !strings.HasPrefix(m.LoadErr(), path+": ") || !strings.Contains(m.LoadErr(), "permission denied") {
		t.Fatalf("LoadErr() = %q, want the path and permission denied", m.LoadErr())
	}
	if got := hitID(m.Set(), "/admin"); got != "block-bad" {
		t.Fatalf("previous rules lost: hit = %q", got)
	}
	if logs != 1 {
		t.Errorf("logged %d times, want once", logs)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	m.reloadIfChanged()
	if m.LoadErr() != "" {
		t.Fatalf("LoadErr() = %q after chmod fix", m.LoadErr())
	}
	if got := hitID(m.Set(), "/other"); got != "block-other" {
		t.Fatalf("fixed file not applied: hit = %q", got)
	}
}

func TestManagerUnreadableAtStartupHasError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of mode")
	}
	path := filepath.Join(t.TempDir(), "rules.yaml")
	writeRules(t, path, goodRulesYAML, time.Now())
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	m := NewManager(path)
	if m.LoadErr() == "" {
		t.Fatal("an unreadable file at startup must show in LoadErr")
	}
}

func TestManagerClearsTransientErrorWithoutFileChange(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory modes")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	writeRules(t, path, goodRulesYAML, time.Now().Add(-time.Hour))
	m := NewManager(path)
	m.logf = func(string, ...any) {}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	m.reloadIfChanged()
	if !strings.Contains(m.LoadErr(), "permission denied") {
		t.Fatalf("LoadErr() = %q, want a permission error", m.LoadErr())
	}
	if got := hitID(m.Set(), "/admin"); got != "block-bad" {
		t.Fatalf("rules lost during the outage: hit = %q", got)
	}

	if err := os.Chmod(dir, 0o700); err != nil { // the file itself is untouched
		t.Fatal(err)
	}
	m.reloadIfChanged()
	if m.LoadErr() != "" {
		t.Fatalf("LoadErr() = %q after recovery, want empty", m.LoadErr())
	}
	if got := hitID(m.Set(), "/admin"); got != "block-bad" {
		t.Fatalf("rules not in force after recovery: hit = %q", got)
	}
	m.reloadIfChanged() // and it stays quiet afterwards
	if m.LoadErr() != "" {
		t.Fatalf("LoadErr() = %q on the next tick", m.LoadErr())
	}
}

func TestManagerEmptyFileReplacesStaleTransientError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of mode")
	}
	path := filepath.Join(t.TempDir(), "rules.yaml")
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	writeRules(t, path, goodRulesYAML, t0)
	m := NewManager(path)
	m.logf = func(string, ...any) {}
	writeRules(t, path, "", t0.Add(time.Minute))
	os.Chmod(path, 0)
	m.reloadIfChanged()
	if !strings.Contains(m.LoadErr(), "permission denied") {
		t.Fatalf("LoadErr() = %q", m.LoadErr())
	}
	os.Chmod(path, 0o600)
	m.reloadIfChanged()
	if e := m.LoadErr(); !strings.Contains(e, "empty") || strings.Contains(e, "permission") {
		t.Fatalf("LoadErr() = %q, want the empty-file message", e)
	}
	if got := hitID(m.Set(), "/admin"); got != "block-bad" {
		t.Fatalf("hit = %q", got)
	}
}

// Save drops expired rules before compiling, but an error must still point
// into the list the caller passed in.
func TestSaveErrorIndexRefersToCallersList(t *testing.T) {
	m := NewManager(filepath.Join(t.TempDir(), "rules.yaml"))
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	past := now.Add(-time.Hour)
	expired := enforce("expired", Match{Paths: []PathMatch{{Prefix: "/a"}}})
	expired.Expires = &past
	noID := enforce("", Match{Paths: []PathMatch{{Prefix: "/b"}}})
	badIP := enforce("bad-ip", Match{IPs: []string{"nope"}})

	err := m.Save([]Rule{expired, noID, expired, badIP})
	if err == nil {
		t.Fatal("Save accepted invalid rules")
	}
	var got []int
	for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
		var re *RuleError
		if !errors.As(e, &re) {
			t.Fatalf("error %v is not a *RuleError", e)
		}
		got = append(got, re.Index)
	}
	if len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Errorf("error indexes = %v, want [1 3] (positions in the list passed to Save)", got)
	}
}
