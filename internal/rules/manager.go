package rules

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// watchEvery is how often Run looks at the rules file, the same as bots.
const watchEvery = 5 * time.Second

// state is one immutable snapshot, swapped in whole so the request path can
// read the compiled set without a lock.
type state struct {
	set     *Set
	rules   []Rule
	mtime   time.Time // of the file as last read or written
	size    int64
	loadErr string // last failed reload; set and rules stay the last good ones
	// transient marks a loadErr that came from stat or read, not from the
	// file's content. The file may be unchanged by the time it is fixed, so
	// while it is set the file is re-read on every tick.
	transient bool
}

// Manager owns the live rule set: it loads the rules file, follows hand edits
// and keeps the last good set when the file is broken.
type Manager struct {
	path  string
	state atomic.Pointer[state]

	mu     sync.Mutex // serialises reloads and saves
	logged string     // last load problem written to the log
	loaded bool       // a file has been applied (read or saved) before

	// Overridable for tests.
	now      func() time.Time
	readFile func(string) ([]byte, error)
	logf     func(format string, args ...any)
	every    time.Duration
}

// NewManager loads path once. A missing file is an empty rule set. A broken
// one is also an empty set (there is no earlier good one), with the problem
// in LoadErr.
func NewManager(path string) *Manager {
	m := &Manager{path: path, now: time.Now, readFile: os.ReadFile, logf: log.Printf, every: watchEvery}
	m.state.Store(&state{set: &Set{}})
	m.reloadIfChanged()
	return m
}

// Run checks the file every few seconds until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.reloadIfChanged()
	t := time.NewTicker(m.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.reloadIfChanged()
		}
	}
}

// Set is the compiled rule set in force. It never blocks and is never nil.
func (m *Manager) Set() *Set { return m.state.Load().set }

// Rules returns a copy of the rules behind Set(); callers may change it freely.
func (m *Manager) Rules() []Rule { return cloneRules(m.state.Load().rules) }

// LoadErr is "" when the file last loaded fine.
func (m *Manager) LoadErr() string { return m.state.Load().loadErr }

// Path is the rules file.
func (m *Manager) Path() string { return m.path }

// reloadIfChanged re-reads the file when its mtime or size changed. A file
// that can't be read, parsed or compiled leaves the current set in force.
func (m *Manager) reloadIfChanged() {
	if m.path == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.state.Load()
	fi, err := os.Stat(m.path)
	if errors.Is(err, fs.ErrNotExist) {
		return // missing is an empty set; a vanished file keeps what is running
	}
	if err != nil {
		m.fail(cur, nil, err.Error())
		return
	}
	// Mtimes can be coarse, so a same-second rewrite is told apart by size.
	if !cur.transient && fi.ModTime().Equal(cur.mtime) && fi.Size() == cur.size {
		return
	}
	data, err := m.readFile(m.path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			m.fail(cur, nil, err.Error()) // not recorded as seen: retried every tick
		}
		return
	}
	// An editor that writes in place can be caught mid-write. If the file moved
	// under the read, take no notice and look again next tick.
	if after, err := os.Stat(m.path); err != nil || !after.ModTime().Equal(fi.ModTime()) || after.Size() != fi.Size() {
		return
	}
	if m.loaded && len(bytes.TrimSpace(data)) == 0 {
		// Most likely a write in progress. Clearing the rules on purpose is "rules: []".
		if msg := m.path + " is empty"; msg != m.logged {
			m.logged = msg
			m.logf("rules: %s is empty; keeping the current rules (write \"rules: []\" to clear them)", m.path)
		}
		if cur.loadErr != "" {
			// Don't leave an older, different problem showing.
			next := *cur
			next.loadErr, next.transient = m.path+": file is empty; keeping the current rules", true
			m.state.Store(&next)
		}
		return
	}
	rs, err := Parse(data)
	if err != nil {
		m.fail(cur, fi, err.Error())
		return
	}
	set, errs := Compile(rs)
	if len(errs) > 0 {
		m.fail(cur, fi, describe(errs))
		return
	}
	m.logged = ""
	m.loaded = true
	m.logf("rules: loaded %d rules from %s", set.Len(), m.path)
	set.inherit(cur.set)
	m.state.Store(&state{set: set, rules: rs, mtime: fi.ModTime(), size: fi.Size()})
}

// fail keeps the current set and rules and records the error. With fi the
// file is remembered as seen, so a broken file is not re-read until it changes
// again; with nil it is retried on every tick.
func (m *Manager) fail(cur *state, fi os.FileInfo, msg string) {
	msg = m.path + ": " + msg
	if msg != m.logged {
		m.logged = msg
		m.logf("rules: not applied, keeping the last good rules: %s", msg)
	}
	next := *cur
	next.loadErr, next.transient = msg, fi == nil
	if fi != nil {
		next.mtime, next.size = fi.ModTime(), fi.Size()
	}
	m.state.Store(&next)
}

// describe reports the first compile error and how many more there were.
func describe(errs []error) string {
	s := errs[0].Error()
	if n := len(errs) - 1; n > 0 {
		s += fmt.Sprintf("; and %d more", n)
	}
	return s
}

// Save stores a new rule list: expired rules are dropped, the rest are
// compiled, and only if all compile is the file written (atomically, 0600)
// and the new set applied. On error nothing is written and the old set stays.
func (m *Manager) Save(rs []Rule) error {
	_, _, err := m.SaveIf(rs, nil)
	return err
}

// SaveIf is Save with a precondition. Once the rules compile, check (when not
// nil) sees the file's bytes as they are now, nil when it is missing, under
// the same lock as the write, so nothing can change the file in between; an
// error from it stops the save. It returns those bytes and the bytes written.
func (m *Manager) SaveIf(rs []Rule, check func(current []byte) error) (before, after []byte, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	keep := make([]Rule, 0, len(rs))
	orig := make([]int, 0, len(rs)) // keep[i] was rs[orig[i]]
	for i, r := range cloneRules(rs) {
		if r.Expires != nil && !r.Expires.After(now) {
			continue
		}
		keep = append(keep, r)
		orig = append(orig, i)
	}
	set, errs := Compile(keep)
	if len(errs) > 0 {
		// Compile saw the pruned list; report positions in the caller's.
		for _, err := range errs {
			var re *RuleError
			if errors.As(err, &re) {
				re.Index = orig[re.Index]
			}
		}
		return nil, nil, errors.Join(errs...)
	}
	if m.path != "" {
		cur, err := os.ReadFile(m.path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		before = cur
	}
	if check != nil {
		if err := check(before); err != nil {
			return nil, nil, err
		}
	}
	next := &state{set: set, rules: keep}
	if m.path != "" {
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(File{Rules: keep}); err != nil {
			return nil, nil, err
		}
		if err := enc.Close(); err != nil {
			return nil, nil, err
		}
		if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
			return nil, nil, err
		}
		fi, err := writeFileAtomic(m.path, buf.Bytes())
		if err != nil {
			return nil, nil, err
		}
		after = buf.Bytes()
		next.mtime, next.size = fi.ModTime(), fi.Size()
		m.loaded = true
	}
	m.logged = ""
	set.inherit(m.state.Load().set)
	m.state.Store(next)
	return before, after, nil
}

// writeFileAtomic writes data to path via a temp file in the same directory,
// so a reader never sees a half-written file. It returns the file's info as
// written, taken before the rename so a later edit can't be mistaken for it.
func writeFileAtomic(path string, data []byte) (os.FileInfo, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rules-*.tmp")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil, err
	}
	fi, err := tmp.Stat()
	if err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return nil, err
	}
	return fi, nil
}

func cloneRules(rs []Rule) []Rule {
	out := make([]Rule, len(rs))
	for i, r := range rs {
		out[i] = r.clone()
	}
	return out
}

func (r Rule) clone() Rule {
	r.Enabled = clonePtr(r.Enabled)
	r.Expires = clonePtr(r.Expires)
	r.Limit = clonePtr(r.Limit)
	if r.API != nil {
		api := *r.API
		api.AllowCookie = clonePtr(api.AllowCookie)
		r.API = &api
	}
	r.Match = r.Match.clone()
	if r.Any != nil {
		groups := make([]Group, len(r.Any))
		for i, g := range r.Any {
			groups[i].All = make([]Condition, len(g.All))
			for j, cd := range g.All {
				groups[i].All[j] = Condition{Match: cd.Match.clone(), Not: cd.Not}
			}
		}
		r.Any = groups
	}
	if r.Except != nil {
		e := r.Except.clone()
		r.Except = &e
	}
	return r
}

func (m Match) clone() Match {
	m.IPs = append([]string(nil), m.IPs...)
	m.ASNs = append([]uint(nil), m.ASNs...)
	m.Hosts = append([]string(nil), m.Hosts...)
	m.Methods = append([]string(nil), m.Methods...)
	m.Paths = append([]PathMatch(nil), m.Paths...)
	m.Headers = append([]HeaderMatch(nil), m.Headers...)
	m.Query = append([]HeaderMatch(nil), m.Query...)
	m.UserAgents = append([]PathMatch(nil), m.UserAgents...)
	m.Countries = append([]string(nil), m.Countries...)
	m.RegisteredCountries = append([]string(nil), m.RegisteredCountries...)
	m.NetworkTypes = append([]string(nil), m.NetworkTypes...)
	m.NetworkRoles = append([]string(nil), m.NetworkRoles...)
	m.Classes = append([]string(nil), m.Classes...)
	m.Lists = append([]string(nil), m.Lists...)
	m.Datacenter = clonePtr(m.Datacenter)
	m.Bots = append([]string(nil), m.Bots...)
	m.Cleared = clonePtr(m.Cleared)
	m.Anomalies = append([]string(nil), m.Anomalies...)
	return m
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
