package aupldb

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// An Overlay classifies addresses from lists that change too often for the
// twice-daily .aupldb build: Tor exits, VPN servers, cloud ranges, verified
// crawlers. Each node fetches the lists itself, straight from their
// publishers, on each list's own cadence; which lists to fetch comes from a
// small JSON manifest (DefaultSources, or a newer copy from ManifestURL).
//
//	ov := &aupldb.Overlay{ManifestURL: "https://api.auplalabs.com/v1/overlay.json", Dir: "/var/lib/waf/overlay"}
//	ov.Load()       // start from the cached lists, if any
//	go ov.Run(ctx)  // then keep them fresh
//	hit := ov.Lookup(ip)
//
// A list that fails to download or parse keeps its previous copy.
type Overlay struct {
	ManifestURL string        // "" = DefaultSources only
	Dir         string        // cache for the manifest and every list
	Interval    time.Duration // how often to check for due lists; default 10 minutes
	Client      *http.Client  // default: 2 minute timeout
	UserAgent   string        // sent to publishers; default "aupldb-overlay/1"
	Logf        func(format string, args ...any)

	idx atomic.Pointer[overlayIndex]

	mu       sync.Mutex // serialises Load and Refresh
	manifest *Manifest
	lists    map[string]*overlayList
}

// Class is a set of overlay classes.
type Class uint16

const (
	ClassTorExit Class = 1 << iota
	ClassVPN
	ClassRelay   // privacy relays meant to be treated like carrier-grade NAT (iCloud Private Relay)
	ClassCrawler // a verified crawler of the named operator
	ClassFetcher // a verified fetcher acting for a person (ChatGPT-User, Perplexity-User)
	ClassHosting // a cloud or hosting provider's published ranges
	ClassCDN     // CDN edge ranges; context only, never a verdict on its own
)

// classOrder is also precedence: the provider shown for an address in
// several lists is the one from the first class here.
var classOrder = []struct {
	c    Class
	name string
}{
	{ClassRelay, "relay"}, {ClassTorExit, "tor_exit"}, {ClassVPN, "vpn"}, {ClassFetcher, "fetcher"},
	{ClassCrawler, "crawler"}, {ClassHosting, "hosting"}, {ClassCDN, "cdn"},
}

func parseClass(s string) (Class, bool) {
	for _, c := range classOrder {
		if c.name == s {
			return c.c, true
		}
	}
	return 0, false
}

func classRank(c Class) int {
	for i, o := range classOrder {
		if o.c == c {
			return i
		}
	}
	return len(classOrder)
}

// Names lists the classes in c, in precedence order.
func (c Class) Names() []string {
	var out []string
	for _, o := range classOrder {
		if c&o.c != 0 {
			out = append(out, o.name)
		}
	}
	return out
}

// Hit is what the overlay knows about an address.
type Hit struct {
	Classes  Class
	Provider string // of the highest-precedence list the address is in
	List     string // that list's source ID, e.g. "mullvad"
	Country  string // from a publisher's own geofeed, when it has one; else ""
}

// Manifest lists the sources an Overlay fetches.
type Manifest struct {
	Version int      `json:"version"`
	Sources []Source `json:"sources"`
}

// Source is one list.
type Source struct {
	ID           string   `json:"id"` // [a-z0-9_]+, also the cache file name
	Class        string   `json:"class"`
	Provider     string   `json:"provider"`
	URL          string   `json:"url"`
	Parser       string   `json:"parser"`            // lines, geofeed, json or regex
	Keys         []string `json:"keys,omitempty"`    // json: the keys whose values are addresses
	Pattern      string   `json:"pattern,omitempty"` // regex: first capture group is an address
	CadenceHours float64  `json:"cadence_hours"`
	Notes        string   `json:"notes,omitempty"`
}

//go:embed overlay-sources.json
var defaultSources []byte

// DefaultSources is the manifest built into this package.
func DefaultSources() []byte { return bytes.Clone(defaultSources) }

var sourceID = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// ParseManifest decodes a manifest, dropping sources this version can't use
// (unknown class or parser, bad ID or URL), so old clients keep working
// when new kinds of sources are added.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("aupldb: overlay manifest: %w", err)
	}
	if m.Version != 1 {
		return nil, fmt.Errorf("aupldb: overlay manifest version %d", m.Version)
	}
	seen := map[string]bool{}
	kept := m.Sources[:0]
	for _, s := range m.Sources {
		_, okClass := parseClass(s.Class)
		okParser := s.Parser == "lines" || s.Parser == "geofeed" || s.Parser == "json" && len(s.Keys) > 0 ||
			s.Parser == "regex" && s.Pattern != ""
		if s.Parser == "regex" && okParser {
			if _, err := regexp.Compile(s.Pattern); err != nil {
				okParser = false
			}
		}
		if !okClass || !okParser || !sourceID.MatchString(s.ID) || seen[s.ID] || !strings.HasPrefix(s.URL, "https://") {
			continue
		}
		if s.CadenceHours <= 0 {
			s.CadenceHours = 24
		}
		seen[s.ID] = true
		kept = append(kept, s)
	}
	m.Sources = kept
	return &m, nil
}

func (s Source) cadence() time.Duration { return time.Duration(s.CadenceHours * float64(time.Hour)) }

// overlayList is one source's current data plus what's needed to refresh it.
type overlayList struct {
	src      Source
	prefixes []geoPrefix
	meta     listMeta
}

type geoPrefix struct {
	p       netip.Prefix
	country string
}

// listMeta is stored next to each cached list.
type listMeta struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`         // last successful fetch (or 304)
	FailedAt     time.Time `json:"failed_at,omitzero"` // last failed attempt since then
	Count        int       `json:"count"`              // prefixes parsed
	Error        string    `json:"error,omitempty"`    // why the last attempt failed
}

// maxListSize bounds what a misbehaving publisher can make us read.
const maxListSize = 64 << 20

func (o *Overlay) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

func (o *Overlay) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

// Lookup returns what the overlay knows about ip; the zero Hit if nothing.
func (o *Overlay) Lookup(ip netip.Addr) Hit {
	idx := o.idx.Load()
	if idx == nil || !ip.IsValid() {
		return Hit{}
	}
	return idx.lookup(ip.Unmap())
}

// Load reads the cached manifest and lists from Dir, so lookups work before
// the first Refresh (and without network).
func (o *Overlay) Load() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.loadManifestLocked()
	for _, s := range o.manifest.Sources {
		if _, ok := o.lists[s.ID]; ok {
			continue
		}
		l := &overlayList{src: s}
		if raw, err := os.ReadFile(filepath.Join(o.Dir, s.ID+".json")); err == nil {
			json.Unmarshal(raw, &l.meta)
		}
		if body, err := os.ReadFile(filepath.Join(o.Dir, s.ID+".list")); err == nil && l.meta.URL == s.URL {
			if ps, err := parseList(s, body); err == nil {
				l.prefixes = ps
			} else {
				l.meta = listMeta{} // unusable cache: fetch again
			}
		} else {
			l.meta = listMeta{}
		}
		o.lists[s.ID] = l
	}
	o.rebuildLocked()
	return nil
}

// loadManifestLocked picks the cached manifest from ManifestURL if there is
// one, else the built-in one.
func (o *Overlay) loadManifestLocked() {
	if o.lists == nil {
		o.lists = map[string]*overlayList{}
	}
	if o.manifest != nil {
		return
	}
	if o.ManifestURL != "" {
		if raw, err := os.ReadFile(filepath.Join(o.Dir, "manifest.json")); err == nil {
			if m, err := ParseManifest(raw); err == nil {
				o.manifest = m
				return
			}
		}
	}
	m, err := ParseManifest(defaultSources)
	if err != nil {
		panic(err) // the embedded manifest is tested
	}
	o.manifest = m
}

// Refresh updates the manifest (at most every 6 hours) and fetches every list
// that is due. It returns the first error, after trying everything.
func (o *Overlay) Refresh(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.loadManifestLocked()
	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return err
	}
	var errs []error
	if err := o.refreshManifestLocked(ctx); err != nil {
		errs = append(errs, err)
	}
	now := time.Now()
	changed := false
	var wg sync.WaitGroup
	var cmu sync.Mutex
	sem := make(chan struct{}, 4) // be gentle with publishers and with us
	for _, s := range o.manifest.Sources {
		l := o.lists[s.ID]
		if l == nil || l.src.URL != s.URL || l.src.Parser != s.Parser {
			l = &overlayList{src: s}
			o.lists[s.ID] = l
			changed = true
		}
		l.src = s
		if !l.due(now) {
			continue
		}
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			ok, err := o.fetchList(ctx, l)
			cmu.Lock()
			defer cmu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", s.ID, err))
			}
			changed = changed || ok
		})
	}
	wg.Wait()
	// Lists dropped from the manifest go away.
	for id := range o.lists {
		if !slices.ContainsFunc(o.manifest.Sources, func(s Source) bool { return s.ID == id }) {
			delete(o.lists, id)
			changed = true
		}
	}
	if changed || o.idx.Load() == nil {
		o.rebuildLocked()
	}
	return errors.Join(errs...)
}

// due: on cadence after a success; after a failure, retry within the hour.
func (l *overlayList) due(now time.Time) bool {
	if l.meta.FetchedAt.IsZero() && l.meta.FailedAt.IsZero() {
		return true
	}
	if !l.meta.FailedAt.IsZero() && l.meta.FailedAt.After(l.meta.FetchedAt) {
		return now.Sub(l.meta.FailedAt) >= min(time.Hour, l.src.cadence())
	}
	return now.Sub(l.meta.FetchedAt) >= l.src.cadence()
}

// manifestEvery is how often the manifest itself is checked.
const manifestEvery = 6 * time.Hour

func (o *Overlay) refreshManifestLocked(ctx context.Context) error {
	if o.ManifestURL == "" {
		return nil
	}
	metaPath := filepath.Join(o.Dir, "manifest.meta.json")
	var meta listMeta
	if raw, err := os.ReadFile(metaPath); err == nil {
		json.Unmarshal(raw, &meta)
	}
	if meta.URL == o.ManifestURL && time.Since(meta.FetchedAt) < manifestEvery && time.Since(meta.FailedAt) < manifestEvery {
		return nil
	}
	body, notModified, err := o.get(ctx, o.ManifestURL, &meta)
	if err == nil && !notModified {
		var m *Manifest
		if m, err = ParseManifest(body); err == nil {
			err = writeAtomic(filepath.Join(o.Dir, "manifest.json"), body)
			o.manifest = m
		}
	}
	if err != nil {
		meta.FailedAt, meta.Error = time.Now(), err.Error()
	} else {
		meta.FetchedAt, meta.Error = time.Now(), ""
	}
	meta.URL = o.ManifestURL
	o.saveMeta(metaPath, meta)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	return nil
}

// fetchList downloads one list if it changed. It reports whether the list's
// data changed.
func (o *Overlay) fetchList(ctx context.Context, l *overlayList) (bool, error) {
	meta := l.meta
	if meta.URL != l.src.URL {
		meta = listMeta{} // new URL: no conditional request
	}
	meta.URL = l.src.URL
	body, notModified, err := o.get(ctx, l.src.URL, &meta)
	var ps []geoPrefix
	if err == nil && !notModified {
		ps, err = parseList(l.src, body)
		if err == nil {
			err = writeAtomic(filepath.Join(o.Dir, l.src.ID+".list"), body)
		}
	}
	metaPath := filepath.Join(o.Dir, l.src.ID+".json")
	if err != nil {
		meta.FailedAt, meta.Error = time.Now(), err.Error()
		meta.ETag, meta.LastModified = l.meta.ETag, l.meta.LastModified // keep validators for the copy we still have
		l.meta = meta
		o.saveMeta(metaPath, meta)
		return false, err
	}
	meta.FetchedAt, meta.FailedAt, meta.Error = time.Now(), time.Time{}, ""
	if notModified {
		meta.Count = len(l.prefixes)
		l.meta = meta
		o.saveMeta(metaPath, meta)
		return false, nil
	}
	meta.Count = len(ps)
	l.prefixes, l.meta = ps, meta
	o.saveMeta(metaPath, meta)
	o.logf("overlay: %s: %d prefixes", l.src.ID, len(ps))
	return true, nil
}

// get fetches url, conditionally on meta's validators, and updates them.
func (o *Overlay) get(ctx context.Context, url string, meta *listMeta) (body []byte, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	ua := o.UserAgent
	if ua == "" {
		ua = "aupldb-overlay/1"
	}
	req.Header.Set("User-Agent", ua)
	if meta.ETag != "" {
		req.Header.Set("If-None-Match", meta.ETag)
	}
	if meta.LastModified != "" {
		req.Header.Set("If-Modified-Since", meta.LastModified)
	}
	resp, err := o.client().Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, true, nil
	case http.StatusOK:
	default:
		return nil, false, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxListSize+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > maxListSize {
		return nil, false, fmt.Errorf("%s is larger than %d bytes", url, maxListSize)
	}
	meta.ETag, meta.LastModified = resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
	return body, false, nil
}

func (o *Overlay) saveMeta(path string, meta listMeta) {
	b, _ := json.MarshalIndent(meta, "", "  ")
	if err := writeAtomic(path, b); err != nil {
		o.logf("overlay: %v", err)
	}
}

// Run calls Refresh every Interval until ctx is done.
func (o *Overlay) Run(ctx context.Context) {
	every := o.Interval
	if every <= 0 {
		every = 10 * time.Minute
	}
	for {
		if err := o.Refresh(ctx); err != nil && ctx.Err() == nil {
			o.logf("overlay: %v (keeping previous copies)", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// ListStatus is one list's state, for dashboards.
type ListStatus struct {
	ID        string    `json:"id"`
	Class     string    `json:"class"`
	Provider  string    `json:"provider"`
	Prefixes  int       `json:"prefixes"`
	FetchedAt time.Time `json:"fetched_at,omitzero"`
	Error     string    `json:"error,omitempty"`
}

// Status reports every list in manifest order.
func (o *Overlay) Status() []ListStatus {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.manifest == nil {
		return nil
	}
	var out []ListStatus
	for _, s := range o.manifest.Sources {
		st := ListStatus{ID: s.ID, Class: s.Class, Provider: s.Provider}
		if l := o.lists[s.ID]; l != nil {
			st.Prefixes, st.FetchedAt, st.Error = len(l.prefixes), l.meta.FetchedAt, l.meta.Error
		}
		out = append(out, st)
	}
	return out
}

// parseList turns a list body into prefixes. An empty result is an error,
// so a publisher serving an empty or changed page can't wipe a list.
func parseList(s Source, body []byte) ([]geoPrefix, error) {
	var out []geoPrefix
	add := func(raw, country string) {
		if p, ok := parseListPrefix(raw); ok {
			out = append(out, geoPrefix{p, country})
		}
	}
	switch s.Parser {
	case "lines", "geofeed":
		sc := bufio.NewScanner(bytes.NewReader(body))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}
			if s.Parser == "lines" {
				if f := strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' }); len(f) > 0 {
					add(f[0], "")
				}
				continue
			}
			f := strings.Split(line, ",")
			cc := ""
			if len(f) > 1 {
				if c := strings.ToUpper(strings.TrimSpace(f[1])); len(c) == 2 && c[0] >= 'A' && c[0] <= 'Z' && c[1] >= 'A' && c[1] <= 'Z' {
					cc = c
				}
			}
			add(f[0], cc)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	case "json":
		var v any
		// Only the first JSON value: some lists append a signature after it.
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&v); err != nil {
			return nil, fmt.Errorf("json: %w", err)
		}
		keys := map[string]bool{}
		for _, k := range s.Keys {
			keys[k] = true
		}
		var walk func(v any, collect bool)
		walk = func(v any, collect bool) {
			switch x := v.(type) {
			case map[string]any:
				for k, val := range x {
					walk(val, keys[k])
				}
			case []any:
				for _, val := range x {
					walk(val, collect)
				}
			case string:
				if collect {
					add(x, "")
				}
			}
		}
		walk(v, false)
	case "regex":
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return nil, err
		}
		for _, m := range re.FindAllSubmatch(body, -1) {
			if len(m) > 1 {
				add(string(m[1]), "")
			}
		}
	default:
		return nil, fmt.Errorf("unknown parser %q", s.Parser)
	}
	if len(out) == 0 {
		return nil, errors.New("no addresses in list")
	}
	return out, nil
}

// parseListPrefix accepts an address or a prefix of global unicast space,
// no wider than /8 (IPv4) or /16 (IPv6): a typo can't cover the internet.
func parseListPrefix(raw string) (netip.Prefix, bool) {
	raw = strings.TrimSpace(raw)
	var p netip.Prefix
	if strings.Contains(raw, "/") {
		var err error
		if p, err = netip.ParsePrefix(raw); err != nil {
			return netip.Prefix{}, false
		}
		p = p.Masked()
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
	} else {
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return netip.Prefix{}, false
		}
		a = a.Unmap()
		p = netip.PrefixFrom(a, a.BitLen())
	}
	a := p.Addr()
	if !p.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || a.Is4() && p.Bits() < 8 || a.Is6() && p.Bits() < 16 {
		return netip.Prefix{}, false
	}
	return p, true
}

// overlayIndex is the merged, flattened form of every list: per family,
// sorted non-overlapping ranges, each with everything known about it.
type overlayIndex struct {
	v4, v6 []overlayRange
}

type overlayRange struct {
	start, end netip.Addr
	hit        Hit
}

func (idx *overlayIndex) lookup(ip netip.Addr) Hit {
	rs := idx.v6
	if ip.Is4() {
		rs = idx.v4
	}
	i := sort.Search(len(rs), func(i int) bool { return ip.Less(rs[i].start) }) - 1
	if i >= 0 && rs[i].end.Compare(ip) >= 0 {
		return rs[i].hit
	}
	return Hit{}
}

// rebuildLocked merges every list into a new index and swaps it in.
func (o *Overlay) rebuildLocked() {
	type member struct {
		lo, hi  netip.Addr
		country string
	}
	type list struct {
		class   Class
		rank    int
		src     Source
		members []member
	}
	var lists []list
	for _, s := range o.manifest.Sources {
		l := o.lists[s.ID]
		if l == nil || len(l.prefixes) == 0 {
			continue
		}
		c, _ := parseClass(s.Class)
		ms := make([]member, 0, len(l.prefixes))
		for _, gp := range l.prefixes {
			ms = append(ms, member{gp.p.Addr(), lastAddr(gp.p), gp.country})
		}
		slices.SortFunc(ms, func(a, b member) int { return a.lo.Compare(b.lo) })
		// Merge overlaps within a list; the first country wins.
		merged := ms[:0]
		for _, m := range ms {
			if n := len(merged); n > 0 && m.lo.Compare(merged[n-1].hi) <= 0 {
				if merged[n-1].hi.Less(m.hi) {
					merged[n-1].hi = m.hi
				}
				continue
			}
			merged = append(merged, m)
		}
		lists = append(lists, list{c, classRank(c), s, merged})
	}
	// Higher precedence first, so the first list containing a point wins.
	slices.SortStableFunc(lists, func(a, b list) int { return a.rank - b.rank })

	idx := &overlayIndex{}
	for _, is4 := range []bool{true, false} {
		var points []netip.Addr
		for _, l := range lists {
			for _, m := range l.members {
				if m.lo.Is4() != is4 {
					continue
				}
				points = append(points, m.lo)
				if n := m.hi.Next(); n.IsValid() {
					points = append(points, n)
				}
			}
		}
		slices.SortFunc(points, netip.Addr.Compare)
		points = slices.Compact(points)
		pos := make([]int, len(lists))
		var out []overlayRange
		for i, p := range points {
			var h Hit
			for j, l := range lists {
				ms := l.members
				for pos[j] < len(ms) && (ms[pos[j]].lo.Is4() != is4 || ms[pos[j]].hi.Less(p)) {
					pos[j]++
				}
				if pos[j] < len(ms) && ms[pos[j]].lo.Compare(p) <= 0 {
					if h.Classes == 0 {
						h.Provider, h.List = l.src.Provider, l.src.ID
					}
					h.Classes |= l.class
					if h.Country == "" {
						h.Country = ms[pos[j]].country
					}
				}
			}
			if h.Classes == 0 {
				continue
			}
			end := points[len(points)-1]
			if i+1 < len(points) {
				end = points[i+1].Prev()
			} else if is4 {
				end = netip.MustParseAddr("255.255.255.255")
			} else {
				end = netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
			}
			if n := len(out); n > 0 && out[n-1].hit == h && out[n-1].end.Next() == p {
				out[n-1].end = end
				continue
			}
			out = append(out, overlayRange{p, end, h})
		}
		if is4 {
			idx.v4 = out
		} else {
			idx.v6 = out
		}
	}
	o.idx.Store(idx)
}

// lastAddr is the highest address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(a)*8; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	out, _ := netip.AddrFromSlice(a)
	return out
}
