// Package badip holds Loupe's known-bad-IP feed: a daily list of addresses
// paired with how many public blacklists currently name each one
// (aggregated upstream from IPsum). The count is the confidence — one list
// can be a stale or noisy entry, a dozen is a scanner nobody disputes — so
// the site turns it into a verdict with two thresholds: listed on
// ChallengeAt or more lists means the Prism puzzle, on BlockAt or more a
// 403.
//
// Loupe fetches the feed itself (conditional GET, so an unchanged list costs
// one 304) and keeps the last good copy on disk, so a restart has the list
// immediately and an upstream outage keeps serving yesterday's. Lookups are
// a map read under an atomic pointer, cheap enough to do on every request.
package badip

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Action is what a listing earns.
type Action int

const (
	None Action = iota
	Challenge
	Block
)

func (a Action) String() string {
	switch a {
	case Challenge:
		return "challenge"
	case Block:
		return "block"
	}
	return "none"
}

// maxLists caps a stored count; the feed's maximum is in the low teens.
const maxLists = 255

// maxBody bounds a download (the full list is ~2 MB as CSV).
const maxBody = 64 << 20

// retryAfterFailure is how soon a failed refresh is retried.
const retryAfterFailure = time.Hour

type Options struct {
	URL         string
	CacheFile   string        // last good list; empty = memory only
	Refresh     time.Duration // how often to re-fetch; default 24h
	ChallengeAt int           // lists ≥ this → Prism; default 1
	BlockAt     int           // lists ≥ this → block; 0 = never
	Client      *http.Client
}

type snapshot struct {
	counts   map[netip.Addr]uint8
	hist     []int // hist[n] = addresses on exactly n lists
	upstream time.Time
	fetched  time.Time
	etag     string
}

// Feed is safe for concurrent use. A nil *Feed is a disabled feed: every
// lookup reports unlisted.
type Feed struct {
	opts Options
	snap atomic.Pointer[snapshot]

	refreshMu sync.Mutex // one fetch at a time

	mu          sync.Mutex // guards the fields below
	lastAttempt time.Time
	lastErr     string
	nextRefresh time.Time
	wake        chan struct{}
}

// New builds a feed and loads the cached copy, if any. It does no network
// I/O; Run does the fetching.
func New(o Options) *Feed {
	if o.Refresh <= 0 {
		o.Refresh = 24 * time.Hour
	}
	if o.ChallengeAt <= 0 {
		o.ChallengeAt = 1
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 60 * time.Second}
	}
	f := &Feed{opts: o, wake: make(chan struct{}, 1)}
	if o.CacheFile != "" {
		if err := f.loadCache(); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("badip: cached list unusable: %v", err)
		}
	}
	return f
}

// Lists reports how many blacklists name ip, 0 if none.
func (f *Feed) Lists(ip net.IP) int {
	if f == nil || ip == nil {
		return 0
	}
	s := f.snap.Load()
	if s == nil {
		return 0
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return 0
	}
	return int(s.counts[a.Unmap()])
}

// Check reports ip's list count and the action it earns.
func (f *Feed) Check(ip net.IP) (lists int, act Action) {
	n := f.Lists(ip)
	return n, f.ActionFor(n)
}

// ActionFor maps a list count to its action under this feed's thresholds.
func (f *Feed) ActionFor(lists int) Action {
	switch {
	case f == nil || lists <= 0:
		return None
	case f.opts.BlockAt > 0 && lists >= f.opts.BlockAt:
		return Block
	case lists >= f.opts.ChallengeAt:
		return Challenge
	}
	return None
}

// Run keeps the list fresh until ctx ends: a fetch now if the cached copy is
// missing or due, then every Refresh, retrying hourly after a failure.
func (f *Feed) Run(ctx context.Context) {
	if f == nil {
		return
	}
	next := time.Now()
	if s := f.snap.Load(); s != nil {
		next = s.fetched.Add(f.opts.Refresh)
	}
	for {
		f.mu.Lock()
		f.nextRefresh = next
		f.mu.Unlock()
		t := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-f.wake:
			t.Stop()
		case <-t.C:
			fctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			f.Refresh(fctx) //nolint:errcheck // recorded in Status
			cancel()
		}
		if f.lastFailed() {
			next = time.Now().Add(min(retryAfterFailure, f.opts.Refresh))
		} else if s := f.snap.Load(); s != nil {
			next = s.fetched.Add(f.opts.Refresh)
		}
	}
}

func (f *Feed) lastFailed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastErr != ""
}

// Refresh fetches the list now. A failure keeps the current list.
func (f *Feed) Refresh(ctx context.Context) error {
	if f == nil {
		return errors.New("the bad-IP feed is disabled")
	}
	f.refreshMu.Lock()
	defer f.refreshMu.Unlock()
	err := f.fetch(ctx)
	f.mu.Lock()
	f.lastAttempt = time.Now()
	f.lastErr = ""
	if err != nil {
		f.lastErr = err.Error()
		log.Printf("badip: refresh failed: %v", err)
	}
	f.mu.Unlock()
	// Let Run reschedule from the new state.
	select {
	case f.wake <- struct{}{}:
	default:
	}
	return err
}

func (f *Feed) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.opts.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Loupe bad-IP feed")
	cur := f.snap.Load()
	if cur != nil && cur.etag != "" {
		req.Header.Set("If-None-Match", cur.etag)
	}
	resp, err := f.opts.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified && cur != nil:
		next := *cur
		next.fetched = time.Now()
		f.snap.Store(&next)
		f.writeMeta(&next)
		return nil
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("%s: HTTP %d", f.opts.URL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return fmt.Errorf("%s: list larger than %d MB", f.opts.URL, maxBody>>20)
	}
	counts, err := Parse(bytes.NewReader(body))
	if err != nil {
		return err
	}
	if len(counts) == 0 {
		// An empty list is far likelier an upstream fault than a clean internet.
		return fmt.Errorf("%s: list is empty, keeping the previous one", f.opts.URL)
	}
	s := newSnapshot(counts)
	s.fetched = time.Now()
	s.etag = resp.Header.Get("ETag")
	s.upstream = upstreamTime(resp.Header)
	f.snap.Store(s)
	if f.opts.CacheFile != "" {
		if err := writeAtomic(f.opts.CacheFile, body); err != nil {
			log.Printf("badip: couldn't cache list: %v", err)
		}
		f.writeMeta(s)
	}
	log.Printf("badip: loaded %d listed addresses", len(counts))
	return nil
}

// upstreamTime is when the list itself last changed: the feed's
// X-Ipsum-Upstream-Updated header, else Last-Modified.
func upstreamTime(h http.Header) time.Time {
	for _, k := range []string{"X-Ipsum-Upstream-Updated", "Last-Modified"} {
		if v := h.Get(k); v != "" {
			if t, err := http.ParseTime(v); err == nil {
				return t
			}
			if t, err := time.Parse(time.RFC1123Z, v); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}

// Parse reads "ip,lists" lines (comma, tab or space separated; a header
// line and # comments are skipped). Unparseable lines are ignored, so one
// bad row can't cost the whole list.
func Parse(r io.Reader) (map[netip.Addr]uint8, error) {
	counts := make(map[netip.Addr]uint8, 128<<10)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.FieldsFunc(line, func(c rune) bool { return c == ',' || c == '\t' || c == ' ' })
		if len(fields) < 2 {
			continue
		}
		a, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n <= 0 {
			continue
		}
		counts[a.Unmap()] = uint8(min(n, maxLists))
	}
	return counts, sc.Err()
}

func newSnapshot(counts map[netip.Addr]uint8) *snapshot {
	top := 0
	for _, n := range counts {
		top = max(top, int(n))
	}
	hist := make([]int, top+1)
	for _, n := range counts {
		hist[n]++
	}
	return &snapshot{counts: counts, hist: hist}
}

// cacheMeta is the sidecar beside the cached list.
type cacheMeta struct {
	ETag     string    `json:"etag,omitempty"`
	Upstream time.Time `json:"upstream,omitempty"`
	Fetched  time.Time `json:"fetched"`
}

func (f *Feed) metaPath() string { return f.opts.CacheFile + ".meta.json" }

func (f *Feed) loadCache() error {
	file, err := os.Open(f.opts.CacheFile)
	if err != nil {
		return err
	}
	defer file.Close()
	counts, err := Parse(file)
	if err != nil {
		return err
	}
	if len(counts) == 0 {
		return errors.New("empty")
	}
	s := newSnapshot(counts)
	var m cacheMeta
	if b, err := os.ReadFile(f.metaPath()); err == nil && json.Unmarshal(b, &m) == nil {
		s.etag, s.upstream, s.fetched = m.ETag, m.Upstream, m.Fetched
	}
	if s.fetched.IsZero() {
		if fi, err := file.Stat(); err == nil {
			s.fetched = fi.ModTime()
		}
	}
	f.snap.Store(s)
	log.Printf("badip: %d listed addresses from cache (fetched %s)", len(counts), s.fetched.Format(time.RFC3339))
	return nil
}

func (f *Feed) writeMeta(s *snapshot) {
	if f.opts.CacheFile == "" {
		return
	}
	b, _ := json.Marshal(cacheMeta{ETag: s.etag, Upstream: s.upstream, Fetched: s.fetched})
	if err := writeAtomic(f.metaPath(), b); err != nil {
		log.Printf("badip: couldn't write cache metadata: %v", err)
	}
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Status is the feed's state for the dashboard.
type Status struct {
	Enabled     bool      `json:"enabled"`
	URL         string    `json:"url,omitempty"`
	Entries     int       `json:"entries"`
	Histogram   []int     `json:"histogram"` // [n] = addresses on exactly n lists
	ChallengeAt int       `json:"challenge_at"`
	BlockAt     int       `json:"block_at"`
	Challenged  int       `json:"challenged"` // listed addresses that get Prism
	Blocked     int       `json:"blocked"`    // listed addresses that are refused
	Upstream    time.Time `json:"upstream_updated,omitzero"`
	Fetched     time.Time `json:"fetched_at,omitzero"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	NextRefresh time.Time `json:"next_refresh,omitzero"`
	RefreshHrs  float64   `json:"refresh_hours"`
}

func (f *Feed) Status() Status {
	if f == nil {
		return Status{Histogram: []int{}}
	}
	st := Status{
		Enabled:     true,
		URL:         f.opts.URL,
		ChallengeAt: f.opts.ChallengeAt,
		BlockAt:     f.opts.BlockAt,
		RefreshHrs:  f.opts.Refresh.Hours(),
		Histogram:   []int{},
	}
	if s := f.snap.Load(); s != nil {
		st.Entries = len(s.counts)
		st.Histogram = s.hist
		st.Upstream, st.Fetched = s.upstream, s.fetched
		for n, c := range s.hist {
			switch f.ActionFor(n) {
			case Block:
				st.Blocked += c
			case Challenge:
				st.Challenged += c
			}
		}
	}
	f.mu.Lock()
	st.LastAttempt, st.LastError, st.NextRefresh = f.lastAttempt, f.lastErr, f.nextRefresh
	f.mu.Unlock()
	return st
}
