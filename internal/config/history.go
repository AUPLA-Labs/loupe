package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Versioned copies of files the dashboard edits (config.yaml, bots.yaml), so
// a bad change can be inspected and rolled back. Each Save writes
// <dir>/<name>/<id>.yaml, where the ID is the UTC save time followed by a
// short content hash. The time has a fixed width, so sorting IDs as strings
// sorts them chronologically.

const historyTimeFormat = "20060102T150405.000Z"

var (
	historyNameRE = regexp.MustCompile(`^[a-z]+$`)
	historyIDRE   = regexp.MustCompile(`^\d{8}T\d{6}\.\d{3}Z-[0-9a-f]{8}$`)
)

// Version describes one saved copy.
type Version struct {
	ID   string    `json:"id"`
	Time time.Time `json:"t"`
	Size int       `json:"size"`
}

// History keeps the newest Keep versions of each named file. A nil *History,
// or one made with an empty dir, does nothing: every method returns zero
// values and nil errors, so callers never need to check whether history is
// configured.
type History struct {
	dir  string
	keep int
	now  func() time.Time // replaced in tests

	mu sync.Mutex
}

// NewHistory returns a History rooted at dir, retaining keep versions of each
// name. An empty dir disables it.
func NewHistory(dir string, keep int) *History {
	if dir == "" {
		return nil
	}
	return &History{dir: dir, keep: keep, now: time.Now}
}

// Save stores data as the newest version of name and returns its ID. Data
// byte-identical to the newest version is not stored again; that version's ID
// is returned instead. Versions beyond keep are then deleted, oldest first.
func (h *History) Save(name string, data []byte) (string, error) {
	if h == nil {
		return "", nil
	}
	if err := checkHistoryName(name); err != nil {
		return "", err
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	versions, err := h.list(name)
	if err != nil {
		return "", err
	}
	if len(versions) > 0 {
		newest := versions[0]
		if old, err := h.get(name, newest.ID); err == nil && bytes.Equal(old, data) {
			return newest.ID, nil
		}
	}

	// Two saves in the same millisecond must still sort in save order.
	t := h.now().UTC().Truncate(time.Millisecond)
	if len(versions) > 0 && !t.After(versions[0].Time) {
		t = versions[0].Time.Add(time.Millisecond)
	}
	sum := sha256.Sum256(data)
	id := t.Format(historyTimeFormat) + "-" + hex.EncodeToString(sum[:4])

	dir := filepath.Join(h.dir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := writeFileAtomic(filepath.Join(dir, id+".yaml"), data); err != nil {
		return "", err
	}

	// Prune the oldest. The new version isn't in the list read above.
	if h.keep > 0 {
		for i := h.keep - 1; i < len(versions); i++ {
			if err := os.Remove(filepath.Join(dir, versions[i].ID+".yaml")); err != nil && !errors.Is(err, os.ErrNotExist) {
				return id, fmt.Errorf("prune history: %w", err)
			}
		}
	}
	return id, nil
}

// List returns the saved versions of name, newest first.
func (h *History) List(name string) ([]Version, error) {
	if h == nil {
		return nil, nil
	}
	if err := checkHistoryName(name); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.list(name)
}

// Get returns the exact bytes saved under id.
func (h *History) Get(name, id string) ([]byte, error) {
	if h == nil {
		return nil, nil
	}
	if err := checkHistoryName(name); err != nil {
		return nil, err
	}
	if !historyIDRE.MatchString(id) {
		return nil, fmt.Errorf("invalid history id %q", id)
	}
	return h.get(name, id)
}

func (h *History) get(name, id string) ([]byte, error) {
	return os.ReadFile(filepath.Join(h.dir, name, id+".yaml"))
}

// list expects a validated name and the lock held.
func (h *History) list(name string) ([]Version, error) {
	entries, err := os.ReadDir(filepath.Join(h.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Version
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".yaml")
		if !ok || e.IsDir() || !historyIDRE.MatchString(id) {
			continue // temp files from an interrupted Save, or strays
		}
		t, err := time.Parse(historyTimeFormat, id[:len(historyTimeFormat)])
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Version{ID: id, Time: t, Size: int(info.Size())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

func checkHistoryName(name string) error {
	if !historyNameRE.MatchString(name) {
		return fmt.Errorf("invalid history name %q", name)
	}
	return nil
}

// writeFileAtomic writes data to path via a temp file in the same directory,
// so a reader never sees a half-written version.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".history-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
