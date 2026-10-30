package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	auditMaxFileBytes = 10 << 20         // a larger file is set aside as .1
	auditKeep         = 5000             // change entries held in memory (the newest)
	auditKeepFailed   = 1000             // failed sign-ins held in memory, apart from changes
	auditMaxPage      = 500              // most entries one Recent call returns
	auditMaxLine      = 1 << 20          // a longer line on disk is skipped when loading
	auditFailWindow   = 10 * time.Minute // repeat failures within this share one entry
)

// AuditEntry is one change made through the dashboard. Time is the instant the
// change succeeded; User is the admin who made it ("" when auth is off).
type AuditEntry struct {
	Time    time.Time `json:"t"`
	User    string    `json:"user"`
	IP      string    `json:"ip"`
	Action  string    `json:"action"`
	Target  string    `json:"target,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	Version string    `json:"version,omitempty"`
	Count   int       `json:"count,omitempty"` // failed sign-ins this entry stands for
}

// failedLogin reports whether e is a failed sign-in, which the public login
// form lets anyone produce, so such entries are coalesced and held apart.
func (e AuditEntry) failedLogin() bool { return e.Action == "login_failed" }

// coalesces reports whether failure next continues e's run: the same address
// and attempted name, within auditFailWindow of the run's first failure.
func (e AuditEntry) coalesces(next AuditEntry) bool {
	return e.IP == next.IP && e.Target == next.Target && next.Time.Sub(e.Time) < auditFailWindow
}

// Audit is an append-only record of dashboard changes: one JSON line per
// entry in a 0600 file, with the newest auditKeep also held in memory. Failed
// sign-ins are kept in their own ring of auditKeepFailed, so a flood of them
// can't push real changes out, and a run of them from one address for one
// name within auditFailWindow is a single entry whose Count goes up. Each
// increase is appended as a line carrying the running count (and the run's
// first Time), and loading keeps only the last line of each run. A nil *Audit
// ignores everything, so callers need no checks.
type Audit struct {
	path string // "" keeps entries in memory only

	mu      sync.Mutex
	entries []AuditEntry // changes, oldest first
	failed  []AuditEntry // failed sign-ins, oldest first
	size    int64        // bytes in the file at path
}

// NewAudit opens the log at path, creating it on the first Add. A file over
// 10 MiB is renamed to path+".1" first (replacing an older one), so the log
// is bounded without ever being rewritten in place; Add rotates the same way
// once the file grows past that. A line longer than 1 MiB is skipped.
func NewAudit(path string) (*Audit, error) {
	a := &Audit{path: path}
	if path == "" {
		return a, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > auditMaxFileBytes {
		if err := os.Rename(path, path+".1"); err != nil {
			return nil, err
		}
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil {
		a.size = fi.Size()
	}
	br := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := readAuditLine(br)
		var e AuditEntry
		if len(line) > 0 && json.Unmarshal(line, &e) == nil { // a torn or foreign line must not hide the rest
			a.load(e)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if len(a.entries) > auditKeep {
		a.entries = append([]AuditEntry(nil), a.entries[len(a.entries)-auditKeep:]...)
	}
	if len(a.failed) > auditKeepFailed {
		a.failed = append([]AuditEntry(nil), a.failed[len(a.failed)-auditKeepFailed:]...)
	}
	return a, nil
}

// load adds an entry read from the file. A failed sign-in carrying the same
// run (address, name and first Time) as the last one replaces it, since each
// line of a run holds its count so far.
func (a *Audit) load(e AuditEntry) {
	if !e.failedLogin() {
		a.entries = append(a.entries, e)
		return
	}
	if e.Count == 0 {
		e.Count = 1 // written before runs were counted
	}
	if n := len(a.failed); n > 0 {
		if last := a.failed[n-1]; last.IP == e.IP && last.Target == e.Target && last.Time.Equal(e.Time) {
			a.failed[n-1] = e
			return
		}
	}
	a.failed = append(a.failed, e)
}

// readAuditLine returns the next line. A line longer than auditMaxLine is
// read through to its newline but returned empty, so it is skipped without
// being buffered whole. The error is io.EOF after the last line.
func readAuditLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	n := 0
	for {
		chunk, err := br.ReadSlice('\n')
		if n += len(chunk); n <= auditMaxLine {
			line = append(line, chunk...)
		} else {
			line = nil
		}
		if err != bufio.ErrBufferFull {
			return line, err
		}
	}
}

// Add records e, stamping it with the current time when it has none. A failed
// sign-in that continues the last one's run raises that entry's Count instead
// of adding another. A failed write is logged: losing an audit line must not
// undo a change already made.
func (a *Audit) Add(e AuditEntry) {
	if a == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch n := len(a.failed); {
	case !e.failedLogin():
		a.entries = pushAudit(a.entries, e, auditKeep)
	case n > 0 && a.failed[n-1].coalesces(e):
		a.failed[n-1].Count++
		e = a.failed[n-1]
	default:
		e.Count = 1
		a.failed = pushAudit(a.failed, e, auditKeepFailed)
	}
	if a.path == "" {
		return
	}
	line, err := json.Marshal(e)
	if err == nil {
		err = a.write(append(line, '\n'))
	}
	if err != nil {
		log.Printf("admin: audit write: %v", err)
	}
}

// pushAudit appends e to ring, dropping the oldest entry once it holds keep.
func pushAudit(ring []AuditEntry, e AuditEntry, keep int) []AuditEntry {
	if len(ring) >= keep {
		copy(ring, ring[1:])
		ring = ring[:keep-1]
	}
	return append(ring, e)
}

// write appends line to the file. When that would take it past 10 MiB the
// file is renamed to path+".1" first and the new one starts with the newest
// entries still held in memory (line's among them), changes before failed
// sign-ins, up to half that size, so a restart keeps them without the copy
// itself filling the file.
func (a *Audit) write(line []byte) error {
	if a.size > 0 && a.size+int64(len(line)) > auditMaxFileBytes {
		if err := os.Rename(a.path, a.path+".1"); err != nil {
			return err
		}
		a.size = 0
		line = nil
		budget := auditMaxFileBytes / 2
		for _, ring := range [][]AuditEntry{a.entries, a.failed} {
			var kept [][]byte
			for i := len(ring) - 1; i >= 0; i-- {
				b, err := json.Marshal(ring[i])
				if err != nil {
					continue
				}
				if budget -= len(b) + 1; budget < 0 {
					break
				}
				kept = append(kept, b)
			}
			for i := len(kept) - 1; i >= 0; i-- {
				line = append(append(line, kept[i]...), '\n')
			}
		}
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, err := f.Write(line)
	a.size += int64(n)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Recent returns up to n entries, newest first, and only those older than
// before when it is non-zero. n is capped at 500.
func (a *Audit) Recent(n int, before time.Time) []AuditEntry {
	if a == nil {
		return nil
	}
	if n > auditMaxPage {
		n = auditMaxPage
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Walk both rings from their newest end, taking the later entry each step.
	var out []AuditEntry
	i, j := len(a.entries)-1, len(a.failed)-1
	for (i >= 0 || j >= 0) && len(out) < n {
		var e AuditEntry
		if j < 0 || (i >= 0 && !a.entries[i].Time.Before(a.failed[j].Time)) {
			e, i = a.entries[i], i-1
		} else {
			e, j = a.failed[j], j-1
		}
		if before.IsZero() || e.Time.Before(before) {
			out = append(out, e)
		}
	}
	return out
}

// SetAudit connects the audit log. Login events are recorded by auth itself,
// since the login route is outside the authenticated mux.
func (s *Server) SetAudit(a *Audit) {
	s.audit.Store(a)
	if s.auth != nil {
		s.auth.audit.Store(a)
	}
}

// auditUser names who is making a change: the session's user, or "" when
// auth is off.
func (s *Server) auditUser(r *http.Request) string {
	u, _ := requestUser(r)
	return u.Username
}

// auditNote is what a handler adds about its change; the middleware supplies
// the rest (who, from where, when).
type auditNote struct {
	target, detail, version string
	skip                    bool // the request changed nothing; record no entry
}

type auditNoteKey struct{}

// noteAudit describes the change being made. It does nothing outside a route
// wrapped by Server.audited.
func noteAudit(r *http.Request, target, detail, version string) {
	if n, ok := r.Context().Value(auditNoteKey{}).(*auditNote); ok {
		n.target, n.detail, n.version = target, detail, version
	}
}

// skipAudit withdraws the entry for a request that succeeded without changing
// anything. Like noteAudit it does nothing outside an audited route.
func skipAudit(r *http.Request) {
	if n, ok := r.Context().Value(auditNoteKey{}).(*auditNote); ok {
		n.skip = true
	}
}

// statusWriter remembers the status a handler wrote. It forwards Flush, which
// handleRestart relies on, and Unwrap for http.ResponseController.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// audited records action in the audit log when h succeeds (status below 400,
// an unwritten status counting as 200). A refused or failed change did not
// happen, so it leaves no entry; nor does one the handler marked with skipAudit.
func (s *Server) audited(action string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		note := &auditNote{}
		sw := &statusWriter{ResponseWriter: w}
		h(sw, r.WithContext(context.WithValue(r.Context(), auditNoteKey{}, note)))
		if sw.status >= http.StatusBadRequest || note.skip {
			return
		}
		s.audit.Load().Add(AuditEntry{
			Time:    time.Now(),
			User:    s.auditUser(r),
			IP:      clientIP(r),
			Action:  action,
			Target:  note.target,
			Detail:  note.detail,
			Version: note.version,
		})
	}
}

// handleAudit returns the newest entries, optionally only those before a
// cursor taken from the last entry of the previous page.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n := 100
	if v := q.Get("n"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil || n < 1 {
			http.Error(w, "n must be a positive integer", http.StatusBadRequest)
			return
		}
	}
	var before time.Time
	if v := strings.TrimSpace(q.Get("before")); v != "" {
		var err error
		if before, err = time.Parse(time.RFC3339Nano, v); err != nil {
			http.Error(w, "before must be an RFC 3339 time", http.StatusBadRequest)
			return
		}
	}
	entries := s.audit.Load().Recent(n, before)
	if entries == nil {
		entries = []AuditEntry{}
	}
	writeJSON(w, struct {
		Entries []AuditEntry `json:"entries"`
	}{entries})
}
