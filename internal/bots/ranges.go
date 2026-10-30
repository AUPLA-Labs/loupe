package bots

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Guard rails against a broken or tampered list: an entry wider than these
// would let a spoofed User-Agent through from a huge slice of the internet.
// Every list Loupe ships with stays well inside them (widest seen: /17).
const (
	minPrefixV4  = 16
	minPrefixV6  = 29
	maxListBytes = 8 << 20
	retryFailed  = time.Hour
)

// rangeSet is one fetched IP list.
type rangeSet struct {
	URL     string
	Nets    []*net.IPNet
	Fetched time.Time // last successful fetch (or cache file time)
	Tried   time.Time // last attempt, successful or not
	Err     string    // last attempt's error; the previous Nets stay in use
}

// SourceStatus is the dashboard's view of one list.
type SourceStatus struct {
	ID       string    `json:"id"`
	Operator string    `json:"operator"`
	URL      string    `json:"url"`
	Count    int       `json:"count"`
	Fetched  time.Time `json:"fetched,omitzero"`
	Tried    time.Time `json:"tried,omitzero"`
	Error    string    `json:"error,omitempty"`
	Bots     []string  `json:"bots"`
}

// parseRanges extracts every IP address and CIDR from a list in any format:
// Google-style JSON ({"prefixes":[{"ipv4Prefix":…}]}), Ahrefs' JSON, plain
// text one-per-line, even an HTML page (Amazon publishes its lists as HTML).
// It tokenises on anything that can't be part of an address, so it doesn't
// need to know the layout. Bare IPs become /32 or /128.
func parseRanges(body []byte) ([]*net.IPNet, error) {
	seen := map[string]bool{}
	var nets []*net.IPNet
	isAddrChar := func(r rune) bool {
		return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == ':' || r == '.' || r == '/'
	}
	for _, tok := range strings.FieldsFunc(string(body), func(r rune) bool { return !isAddrChar(r) }) {
		tok = strings.Trim(tok, ".:/")
		if !strings.ContainsAny(tok, ".:") {
			continue
		}
		n := parseNet(tok)
		if n == nil {
			continue
		}
		ones, bits := n.Mask.Size()
		if (bits == 32 && ones < minPrefixV4) || (bits == 128 && ones < minPrefixV6) {
			return nil, fmt.Errorf("list contains %s, wider than Loupe accepts (/%d IPv4, /%d IPv6)", n, minPrefixV4, minPrefixV6)
		}
		if n.IP.IsLoopback() || n.IP.IsPrivate() || n.IP.IsUnspecified() || n.IP.IsLinkLocalUnicast() {
			continue
		}
		if k := n.String(); !seen[k] {
			seen[k] = true
			nets = append(nets, n)
		}
	}
	if len(nets) == 0 {
		return nil, errors.New("no IP ranges found in the response")
	}
	return nets, nil
}

func parseNet(s string) *net.IPNet {
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil
		}
		return n
	}
	// A bare IPv6 token needs at least two colons; anything less is a
	// timestamp or ratio that happens to be hex.
	if strings.Count(s, ":") == 1 {
		return nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func containsIP(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// rangeStore fetches, caches and serves IP lists by URL.
type rangeStore struct {
	dir     string
	refresh time.Duration
	client  *http.Client

	mu   sync.RWMutex
	sets map[string]*rangeSet

	fetching sync.Map // url -> struct{}, so one URL is never fetched twice at once
}

func newRangeStore(dir string, refresh time.Duration) *rangeStore {
	return &rangeStore{
		dir:     dir,
		refresh: refresh,
		client:  &http.Client{Timeout: 30 * time.Second},
		sets:    make(map[string]*rangeSet),
	}
}

func (s *rangeStore) cachePath(url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:8])+".txt")
}

// nets returns the current ranges for url (nil if never loaded).
func (s *rangeStore) nets(url string) []*net.IPNet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if rs := s.sets[url]; rs != nil {
		return rs.Nets
	}
	return nil
}

func (s *rangeStore) status(url string) rangeSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if rs := s.sets[url]; rs != nil {
		return *rs
	}
	return rangeSet{URL: url}
}

// loadCached reads url's cache file, if any, so verification works from the
// first request after a restart without waiting on the network.
func (s *rangeStore) loadCached(url string) {
	path := s.cachePath(url)
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	fi, _ := f.Stat()
	var nets []*net.IPNet
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if n := parseNet(line); n != nil {
			nets = append(nets, n)
		}
	}
	if len(nets) == 0 {
		return
	}
	s.mu.Lock()
	if s.sets[url] == nil {
		s.sets[url] = &rangeSet{URL: url, Nets: nets, Fetched: fi.ModTime(), Tried: fi.ModTime()}
	}
	s.mu.Unlock()
}

// due reports whether url should be fetched now.
func (s *rangeStore) due(url string) bool {
	rs := s.status(url)
	if rs.Tried.IsZero() {
		return true
	}
	if rs.Err != "" {
		return time.Since(rs.Tried) > retryFailed
	}
	return time.Since(rs.Fetched) > s.refresh
}

// fetch downloads and parses url. On failure the previous ranges stay in use.
func (s *rangeStore) fetch(ctx context.Context, url string) error {
	if _, busy := s.fetching.LoadOrStore(url, struct{}{}); busy {
		return nil
	}
	defer s.fetching.Delete(url)

	nets, err := s.download(ctx, url)
	now := time.Now()
	s.mu.Lock()
	rs := s.sets[url]
	if rs == nil {
		rs = &rangeSet{URL: url}
		s.sets[url] = rs
	}
	rs.Tried = now
	if err != nil {
		rs.Err = err.Error()
	} else {
		rs.Nets, rs.Fetched, rs.Err = nets, now, ""
	}
	s.mu.Unlock()

	if err != nil {
		log.Printf("bots: fetch %s: %v", url, err)
		return err
	}
	if werr := s.writeCache(url, nets); werr != nil {
		log.Printf("bots: cache %s: %v", url, werr)
	}
	return nil
}

func (s *rangeStore) download(ctx context.Context, url string) ([]*net.IPNet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Loupe/1.0 (verified-bot IP list refresh)")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxListBytes {
		return nil, fmt.Errorf("list larger than %d MB", maxListBytes>>20)
	}
	return parseRanges(body)
}

func (s *rangeStore) writeCache(url string, nets []*net.IPNet) error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# %s\n# fetched %s, %d ranges\n", url, time.Now().UTC().Format(time.RFC3339), len(nets))
	for _, n := range nets {
		b.WriteString(n.String())
		b.WriteByte('\n')
	}
	path := s.cachePath(url)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// refreshDue fetches every due URL, a few at a time.
func (s *rangeStore) refreshDue(ctx context.Context, urls []string, force bool) {
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, u := range urls {
		if !force && !s.due(u) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer func() { <-sem; wg.Done() }()
			s.fetch(ctx, u)
		}(u)
	}
	wg.Wait()
}
