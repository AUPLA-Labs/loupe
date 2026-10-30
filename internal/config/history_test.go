package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHistorySaveListGet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history")
	h := NewHistory(dir, 50)

	first, err := h.Save("config", []byte("a: 1\n"))
	if err != nil {
		t.Fatalf("Save first: %v", err)
	}
	second, err := h.Save("config", []byte("a: 2\n"))
	if err != nil {
		t.Fatalf("Save second: %v", err)
	}
	if first == second {
		t.Fatalf("different content got the same id %q", first)
	}

	vs, err := h.List("config")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(vs) != 2 {
		t.Fatalf("List returned %d versions, want 2", len(vs))
	}
	if vs[0].ID != second || vs[1].ID != first {
		t.Errorf("List order = [%s %s], want newest first [%s %s]", vs[0].ID, vs[1].ID, second, first)
	}
	if vs[0].Size != len("a: 2\n") || vs[0].Time.IsZero() {
		t.Errorf("newest version = %+v, want size 5 and a non-zero time", vs[0])
	}

	got, err := h.Get("config", first)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "a: 1\n" {
		t.Errorf("Get = %q, want the exact bytes saved", got)
	}

	fi, err := os.Stat(filepath.Join(dir, "config", first+".yaml"))
	if err != nil {
		t.Fatalf("stat version file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("version file mode = %v, want 0600", fi.Mode().Perm())
	}
	for _, d := range []string{dir, filepath.Join(dir, "config")} {
		di, err := os.Stat(d)
		if err != nil {
			t.Fatalf("stat %s: %v", d, err)
		}
		if di.Mode().Perm() != 0o700 {
			t.Errorf("%s mode = %v, want 0700", d, di.Mode().Perm())
		}
	}
}

func TestHistoryDedupesIdenticalContent(t *testing.T) {
	h := NewHistory(t.TempDir(), 50)

	a1, _ := h.Save("config", []byte("x\n"))
	a2, err := h.Save("config", []byte("x\n"))
	if err != nil {
		t.Fatalf("Save duplicate: %v", err)
	}
	if a1 != a2 {
		t.Errorf("duplicate save returned %q, want the newest id %q", a2, a1)
	}
	if vs, _ := h.List("config"); len(vs) != 1 {
		t.Fatalf("after Save(x), Save(x): %d versions, want 1", len(vs))
	}

	if _, err := h.Save("config", []byte("y\n")); err != nil {
		t.Fatalf("Save y: %v", err)
	}
	if _, err := h.Save("config", []byte("x\n")); err != nil {
		t.Fatalf("Save x again: %v", err)
	}
	if vs, _ := h.List("config"); len(vs) != 3 {
		t.Errorf("after x, y, x: %d versions, want 3 (only the newest is compared)", len(vs))
	}
}

func TestHistoryPrunesBeyondKeep(t *testing.T) {
	h := NewHistory(t.TempDir(), 3)

	var ids []string
	for _, s := range []string{"1\n", "2\n", "3\n", "4\n", "5\n"} {
		id, err := h.Save("config", []byte(s))
		if err != nil {
			t.Fatalf("Save %q: %v", s, err)
		}
		ids = append(ids, id)
	}

	vs, err := h.List("config")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(vs) != 3 {
		t.Fatalf("kept %d versions, want 3", len(vs))
	}
	for i, want := range []string{ids[4], ids[3], ids[2]} {
		if vs[i].ID != want {
			t.Errorf("version %d = %s, want %s (the 3 newest)", i, vs[i].ID, want)
		}
	}
}

func TestHistoryOrdersSavesInTheSameMillisecond(t *testing.T) {
	h := NewHistory(t.TempDir(), 50)
	frozen := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return frozen }

	var ids []string
	for _, s := range []string{"a\n", "b\n", "c\n"} {
		id, err := h.Save("config", []byte(s))
		if err != nil {
			t.Fatalf("Save %q: %v", s, err)
		}
		ids = append(ids, id)
	}
	vs, err := h.List("config")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(vs) != 3 || vs[0].ID != ids[2] || vs[1].ID != ids[1] || vs[2].ID != ids[0] {
		t.Errorf("List = %v, want the saves newest first %v even with a frozen clock", vs, ids)
	}
}

func TestHistoryRejectsBadNamesAndIDs(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "history")
	h := NewHistory(dir, 50)
	good, err := h.Save("config", []byte("ok\n"))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	// A file outside the history dir that a traversal would reach.
	if err := os.WriteFile(filepath.Join(root, "secret.yaml"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"../x", "Config", "", "a/b", "con-fig"} {
		if _, err := h.Save(name, []byte("x")); err == nil {
			t.Errorf("Save(%q) succeeded, want error", name)
		}
		if _, err := h.List(name); err == nil {
			t.Errorf("List(%q) succeeded, want error", name)
		}
		if _, err := h.Get(name, good); err == nil {
			t.Errorf("Get(%q, valid id) succeeded, want error", name)
		}
	}
	for _, id := range []string{"../../etc/passwd", "x", "", "../secret", good + "/..", strings.ToUpper(good)} {
		if _, err := h.Get("config", id); err == nil {
			t.Errorf("Get(config, %q) succeeded, want error", id)
		}
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("root has %d entries after rejected calls, want only history and secret.yaml", len(entries))
	}
}

func TestHistoryNilIsNoOp(t *testing.T) {
	var nilHist *History
	for name, h := range map[string]*History{
		"nil pointer": nilHist,
		"empty dir":   NewHistory("", 50),
	} {
		id, err := h.Save("config", []byte("x"))
		if id != "" || err != nil {
			t.Errorf("%s: Save = %q, %v; want zero values", name, id, err)
		}
		vs, err := h.List("config")
		if vs != nil || err != nil {
			t.Errorf("%s: List = %v, %v; want nil, nil", name, vs, err)
		}
		b, err := h.Get("config", "anything")
		if b != nil || err != nil {
			t.Errorf("%s: Get = %q, %v; want nil, nil", name, b, err)
		}
	}
}

func TestAdminHistoryDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	a := cfg.Admin
	if a.AuditPath != "data/audit.jsonl" || a.HistoryDir != "data/history" || a.HistoryKeep != 50 {
		t.Errorf("admin defaults = %q, %q, %d; want data/audit.jsonl, data/history, 50", a.AuditPath, a.HistoryDir, a.HistoryKeep)
	}
}

func TestAdminHistoryKeepAtLeastTwo(t *testing.T) {
	tests := []struct {
		keep, want int
	}{
		{0, 50},
		{-3, 50},
		{1, 2},
		{2, 2},
		{7, 7},
	}
	for _, tt := range tests {
		cfg, err := LoadBytes([]byte(fmt.Sprintf("backend: http://127.0.0.1:8081\nadmin:\n  history_keep: %d\n", tt.keep)))
		if err != nil {
			t.Fatalf("history_keep %d: LoadBytes: %v", tt.keep, err)
		}
		if got := cfg.Admin.HistoryKeep; got != tt.want {
			t.Errorf("history_keep %d loaded as %d, want %d", tt.keep, got, tt.want)
		}
	}
}
