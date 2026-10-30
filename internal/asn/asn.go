package asn

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/aupldb"
)

// Record is everything Loupe knows about an address's network: the AUPLA
// database's record, plus what the overlay's published lists say about the
// address itself.
type Record struct {
	ASN               uint     `json:"asn,omitempty"` // 0 = not routed (or no data yet)
	Org               string   `json:"org,omitempty"`
	Category          string   `json:"category,omitempty"`     // isp, business, hosting, education_research, government_admin
	Role              string   `json:"network_role,omitempty"` // stub, access_provider, … tier1_transit
	Country           string   `json:"country,omitempty"`      // where the address is used: the publisher's geofeed, else the database
	RegisteredCountry string   `json:"registered_country,omitempty"`
	RIR               string   `json:"rir,omitempty"`
	Allocated         string   `json:"allocated,omitempty"` // YYYY-MM-DD
	RangeStart        string   `json:"range_start,omitempty"`
	RangeEnd          string   `json:"range_end,omitempty"`
	MOAS              bool     `json:"moas,omitempty"`
	Classes           []string `json:"classes,omitempty"`  // from the overlay: tor_exit, vpn, relay, crawler, fetcher, hosting, cdn
	Provider          string   `json:"provider,omitempty"` // the overlay list's provider, e.g. "Mullvad"
	List              string   `json:"list,omitempty"`     // and its ID, e.g. "mullvad"
	Datacenter        bool     `json:"datacenter"`         // see DB.datacenter
}

// HasClass reports whether the overlay put the address in class c.
func (r Record) HasClass(c string) bool { return slices.Contains(r.Classes, c) }

// Options says where the AUPLA database and the overlay lists come from.
type Options struct {
	Path      string        // local copy, read at startup and kept current
	API       string        // AUPLA API base URL, e.g. https://api.auplalabs.com
	TokenFile string        // this install's token, written once the terms are accepted
	Interval  time.Duration // how often to check for a new database build
	// PublicKeys are the base64 Ed25519 keys a database must be signed by;
	// none means aupldb.DefaultPublicKeys, AUPLA's own.
	PublicKeys []string
	OnName     func(asn uint, name string)

	// DatacenterCategories are the network types (ipverse categories, e.g.
	// "hosting") that count as datacenters, on top of the listed ASNs.
	DatacenterCategories []string
	// OverlayDir caches the overlay lists (Tor exits, VPN servers, clouds,
	// verified crawlers), which Loupe fetches from their publishers; "" = no
	// overlay.
	OverlayDir string
	UserAgent  string // sent to list publishers

	// DatacenterListURL is a published list of datacenter ASNs, in the
	// datacenter file's format, that Loupe keeps the file current from
	// every DatacenterListRefresh (default a week); "" = the file is
	// maintained by hand.
	DatacenterListURL     string
	DatacenterListRefresh time.Duration
}

type DB struct {
	api, tokenFile string
	client         *http.Client
	src            *aupldb.Updater
	overlay        *aupldb.Overlay // nil when disabled
	onName         func(asn uint, name string)
	blockedASNs    map[uint]bool
	allowedASNs    map[uint]bool
	datacenterASNs map[uint]bool // listed in config
	dcCategories   map[aupldb.Category]bool

	// The datacenter file's ASNs, swapped whole when the list is refreshed.
	dcList                 atomic.Pointer[map[uint]bool]
	dcURL, dcFile, dcAgent string
	dcEvery                time.Duration
	dcMu                   sync.Mutex // serialises refreshes; guards dcETag
	dcETag                 string

	idx      atomic.Pointer[asnIndex]
	idxMu    sync.Mutex
	pendMu   sync.Mutex
	pendings map[uint]bool // names asked for before the database had them
}

// asnIndex is the per-ASN part of a database, for questions about a network
// rather than an address.
type asnIndex struct {
	db   *aupldb.DB
	asns map[uint32]ASNInfo
}

// ASNInfo is what the database says about a network as a whole.
type ASNInfo struct {
	Name              string `json:"org,omitempty"`
	Category          string `json:"category,omitempty"`
	Role              string `json:"network_role,omitempty"`
	RegisteredCountry string `json:"registered_country,omitempty"`
	RIR               string `json:"rir,omitempty"`
}

// New loads the local copy of the database, or downloads it when there is
// none yet. Without a token (the AUPLA terms not accepted yet) or any copy,
// Loupe runs without network data: every address looks unrouted until the
// terms are accepted in the dashboard (Accept). Run keeps it current.
func New(opts Options, blockedASNs, allowedASNs, datacenterASNs []uint, datacenterFile string) (*DB, error) {
	api := strings.TrimRight(opts.API, "/")
	url := ""
	if api != "" {
		url = api + "/v1/asn.aupldb"
	}
	keys := aupldb.DefaultPublicKeys
	if len(opts.PublicKeys) > 0 {
		keys = nil
		for _, k := range opts.PublicKeys {
			pub, err := aupldb.ParsePublicKey(k)
			if err != nil {
				return nil, fmt.Errorf("asn public keys: %w", err)
			}
			keys = append(keys, pub)
		}
	}
	src := &aupldb.Updater{URL: url, Path: opts.Path, Interval: opts.Interval, PublicKeys: keys, Logf: log.Printf}
	tok, err := readToken(opts.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("asn token: %w", err)
	}
	src.SetToken(tok)
	if err := src.Load(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("asn: local copy %s unusable: %v", opts.Path, err)
		}
		if tok == "" {
			log.Printf("asn: no AUPLA token yet; running without network data until the terms are accepted in the dashboard")
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			_, err := src.Refresh(ctx)
			cancel()
			if err != nil {
				log.Printf("asn: no network data yet, will keep trying: %v", err)
			}
		}
	}
	blocked := make(map[uint]bool, len(blockedASNs))
	for _, n := range blockedASNs {
		blocked[n] = true
	}
	allowed := make(map[uint]bool, len(allowedASNs))
	for _, n := range allowedASNs {
		allowed[n] = true
	}
	dc := make(map[uint]bool, len(datacenterASNs))
	for _, n := range datacenterASNs {
		dc[n] = true
	}
	listed := map[uint]bool{}
	if datacenterFile != "" {
		// A file that a list download will create is allowed to be missing.
		err := loadASNFile(datacenterFile, listed)
		if err != nil && !(errors.Is(err, os.ErrNotExist) && opts.DatacenterListURL != "") {
			return nil, fmt.Errorf("load datacenter ASN file: %w", err)
		}
	}
	cats := map[aupldb.Category]bool{}
	for _, c := range opts.DatacenterCategories {
		cat, ok := aupldb.ParseCategory(c)
		if !ok {
			return nil, fmt.Errorf("asn.datacenter_categories: unknown network type %q", c)
		}
		cats[cat] = true
	}
	d := &DB{
		api: api, tokenFile: opts.TokenFile, client: &http.Client{Timeout: 30 * time.Second},
		src: src, onName: opts.OnName, blockedASNs: blocked, allowedASNs: allowed, datacenterASNs: dc, dcCategories: cats,
		dcFile: datacenterFile, dcAgent: opts.UserAgent, dcEvery: opts.DatacenterListRefresh,
	}
	if datacenterFile != "" {
		d.dcURL = opts.DatacenterListURL
	}
	if d.dcEvery <= 0 {
		d.dcEvery = 7 * 24 * time.Hour
	}
	d.dcList.Store(&listed)
	if opts.OverlayDir != "" {
		ov := &aupldb.Overlay{Dir: opts.OverlayDir, UserAgent: opts.UserAgent, Logf: log.Printf}
		if api != "" {
			ov.ManifestURL = api + "/v1/overlay.json"
		}
		ov.Load()
		d.overlay = ov
	}
	return d, nil
}

// readToken returns the first line of path, or "" when path is unset or
// doesn't exist yet.
func readToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	tok, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(tok), nil
}

// Run checks for a new database build every Interval and keeps the overlay
// lists fresh, until ctx is done. Names asked for before the database had
// them are reported (OnName) once a build that has them is in place.
func (d *DB) Run(ctx context.Context) {
	if d.overlay != nil {
		go d.overlay.Run(ctx)
	}
	if d.dcURL != "" {
		go d.runDatacenterList(ctx)
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			d.flushNames()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	d.src.Run(ctx)
}

// index returns the per-ASN index of the current database, rebuilding it
// when a new build was installed; nil without data.
func (d *DB) index() *asnIndex {
	db := d.src.DB()
	if db == nil {
		return nil
	}
	if idx := d.idx.Load(); idx != nil && idx.db == db {
		return idx
	}
	d.idxMu.Lock()
	defer d.idxMu.Unlock()
	if idx := d.idx.Load(); idx != nil && idx.db == db {
		return idx
	}
	idx := &asnIndex{db: db, asns: map[uint32]ASNInfo{}}
	for _, rec := range db.All() {
		if rec.ASN == 0 {
			continue
		}
		if _, ok := idx.asns[rec.ASN]; ok {
			continue
		}
		idx.asns[rec.ASN] = ASNInfo{Name: rec.Name, Category: rec.Category.String(), Role: rec.Role.String(),
			RegisteredCountry: rec.RegisteredCountry, RIR: rec.RIR.String()}
	}
	d.idx.Store(idx)
	return idx
}

// Info is what the database says about asn as a network; zero if it has
// nothing (unrouted, or no data yet).
func (d *DB) Info(asn uint) ASNInfo {
	if idx := d.index(); idx != nil && asn <= math.MaxUint32 {
		return idx.asns[uint32(asn)]
	}
	return ASNInfo{}
}

// NameOf returns asn's AS name, or "" if the database has none. A name
// missing only because no database is loaded yet is reported through
// OnName once one is.
func (d *DB) NameOf(asn uint) string {
	if asn == 0 {
		return ""
	}
	if d.index() == nil {
		d.QueueNames([]uint{asn})
		return ""
	}
	return d.Info(asn).Name
}

// CachedName returns asn's AS name, or "" if the database has none.
func (d *DB) CachedName(asn uint) string { return d.Info(asn).Name }

// QueueNames reports (OnName) the names of asns, e.g. for events logged
// before their names were known: right away when the database has them,
// else once a database is loaded.
func (d *DB) QueueNames(asns []uint) {
	d.pendMu.Lock()
	if d.pendings == nil {
		d.pendings = map[uint]bool{}
	}
	for _, a := range asns {
		if a != 0 {
			d.pendings[a] = true
		}
	}
	d.pendMu.Unlock()
	d.flushNames()
}

func (d *DB) flushNames() {
	idx := d.index()
	if idx == nil {
		return
	}
	d.pendMu.Lock()
	pend := d.pendings
	d.pendings = nil
	d.pendMu.Unlock()
	if d.onName == nil {
		return
	}
	for a := range pend {
		if n := idx.asns[uint32(a)].Name; n != "" {
			d.onName(a, n)
		}
	}
}

// Status reports the loaded build, the last download attempt and whether
// the AUPLA terms still need accepting.
func (d *DB) Status() aupldb.Status { return d.src.Status() }

// OverlayStatus reports every overlay list; nil when the overlay is off.
func (d *DB) OverlayStatus() []aupldb.ListStatus {
	if d.overlay == nil {
		return nil
	}
	return d.overlay.Status()
}

// Terms are AUPLA's terms for the network data, as GET /v1/terms serves them.
type Terms struct {
	Version    string   `json:"version"`
	Title      string   `json:"title"`
	Paragraphs []string `json:"paragraphs"`
}

// ErrTermsChanged means AUPLA published new terms since they were shown.
var ErrTermsChanged = errors.New("the AUPLA terms changed since they were shown; please review them again")

// Terms fetches the current terms from the AUPLA API.
func (d *DB) Terms(ctx context.Context) (Terms, error) {
	var t Terms
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.api+"/v1/terms", nil)
	if err != nil {
		return t, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return t, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return t, fmt.Errorf("%s/v1/terms returned %s", d.api, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t); err != nil {
		return t, fmt.Errorf("decode terms: %w", err)
	}
	if t.Version == "" || len(t.Paragraphs) == 0 {
		return t, errors.New("the AUPLA API returned empty terms")
	}
	return t, nil
}

// Accept tells AUPLA this install accepts terms version, saves the token it
// issues and starts using it right away. software identifies Loupe, e.g.
// "loupe/v1.2.0"; the instance label is this server's hostname.
func (d *DB) Accept(ctx context.Context, version, software string) error {
	if d.tokenFile == "" {
		return errors.New("asn.token_file is not set, so the token can't be saved")
	}
	host, _ := os.Hostname()
	body, _ := json.Marshal(map[string]string{"accept": version, "instance": host, "software": software})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.api+"/v1/tokens", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		Token string `json:"token"`
		Error string `json:"error"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	switch {
	case resp.StatusCode == http.StatusConflict:
		return ErrTermsChanged
	case resp.StatusCode != http.StatusCreated || out.Token == "":
		msg := resp.Status
		if out.Error != "" {
			msg += ": " + out.Error
		}
		return fmt.Errorf("AUPLA refused the registration (%s)", msg)
	}
	if err := writeToken(d.tokenFile, out.Token); err != nil {
		return fmt.Errorf("save token: %w", err)
	}
	d.src.SetToken(out.Token)
	d.src.Kick()
	log.Printf("asn: AUPLA terms %s accepted, token saved to %s", version, d.tokenFile)
	return nil
}

// writeToken saves tok readable by this user only.
func writeToken(path, tok string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".token-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(tok + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// loadASNFile parses a file of lines like "AS12345 Some Org Name" into dst.
// Blank lines and lines starting with '#' are ignored.
func loadASNFile(path string, dst map[uint]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return parseASNs(f, dst)
}

// parseASNs reads loadASNFile's format from r into dst.
func parseASNs(r io.Reader, dst map[uint]bool) error {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip leading "AS" prefix (case-insensitive).
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "AS") {
			line = line[2:]
		}
		// ASN is everything up to the first space.
		field := strings.SplitN(line, " ", 2)[0]
		n, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			continue // skip malformed lines
		}
		dst[uint(n)] = true
	}
	return sc.Err()
}

// Lookup returns everything known about ip's network. ASN 0 means the
// address isn't routed, or no database is loaded yet (the overlay may still
// know the address). It costs two binary searches.
func (d *DB) Lookup(ip net.IP) (Record, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return Record{}, fmt.Errorf("lookup %s: not an IP address", ip)
	}
	addr = addr.Unmap()
	var out Record
	var cat aupldb.Category
	if db := d.src.DB(); db != nil {
		rec, rg, _ := db.Lookup(addr)
		cat = rec.Category
		out = Record{
			ASN: uint(rec.ASN), Org: rec.Name, Category: rec.Category.String(), Role: rec.Role.String(),
			Country: rec.Country, RegisteredCountry: rec.RegisteredCountry, RIR: rec.RIR.String(), MOAS: rec.MOAS(),
			RangeStart: rg.Start.String(), RangeEnd: rg.End.String(),
		}
		if a := rec.Allocated; a != 0 {
			out.Allocated = fmt.Sprintf("%04d-%02d-%02d", a/10000, a/100%100, a%100)
		}
	}
	var hit aupldb.Hit
	if d.overlay != nil {
		hit = d.overlay.Lookup(addr)
		out.Classes, out.Provider, out.List = hit.Classes.Names(), hit.Provider, hit.List
		if hit.Country != "" {
			out.Country = hit.Country // the operator's own geofeed beats the database
		}
	}
	out.Datacenter = d.datacenter(out.ASN, cat, hit)
	return out, nil
}

// datacenter decides whether an address counts as a datacenter one: in a
// cloud's published ranges, or in a listed network, or in a network whose
// type is one of DatacenterCategories. Privacy relays (iCloud Private Relay
// sits in Akamai and Cloudflare space) and verified crawlers and fetchers
// never count: their published lists are more specific than their network.
func (d *DB) datacenter(asn uint, cat aupldb.Category, hit aupldb.Hit) bool {
	switch {
	case hit.Classes&(aupldb.ClassRelay|aupldb.ClassCrawler|aupldb.ClassFetcher) != 0:
		return false
	case hit.Classes&aupldb.ClassHosting != 0:
		return true
	case asn == 0:
		return false
	}
	return d.listedDatacenter(asn) || d.dcCategories[cat]
}

// listedDatacenter reports whether config or the datacenter file lists asn.
func (d *DB) listedDatacenter(asn uint) bool {
	return d.datacenterASNs[asn] || (*d.dcList.Load())[asn]
}

func (d *DB) IsAllowed(asn uint) bool { return d.allowedASNs[asn] }
func (d *DB) IsBlocked(asn uint) bool { return d.blockedASNs[asn] }

// IsDatacenter reports whether a whole network counts as a datacenter: it
// is listed, or its type is one of DatacenterCategories. For an address,
// Lookup's Datacenter is more precise.
func (d *DB) IsDatacenter(asn uint) bool {
	if d.listedDatacenter(asn) {
		return true
	}
	if len(d.dcCategories) == 0 || asn == 0 {
		return false
	}
	cat, _ := aupldb.ParseCategory(d.Info(asn).Category)
	return d.dcCategories[cat]
}
