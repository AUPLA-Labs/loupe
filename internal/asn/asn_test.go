package asn

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/aupldb"
)

func testDB() []byte {
	a := netip.MustParseAddr
	return aupldb.Build(time.Now(),
		[]aupldb.Entry{
			{Start: a("0.0.0.0")},
			{Start: a("8.8.8.0"), Record: aupldb.Record{ASN: 15169, Name: "Google LLC", Category: aupldb.CategoryHosting,
				Role: aupldb.RoleMidsizeTransit, Country: "US", RegisteredCountry: "US", RIR: aupldb.RIRARIN, Allocated: 20231228}},
			{Start: a("8.8.9.0")},
			{Start: a("80.128.0.0"), Record: aupldb.Record{ASN: 3320, Name: "Deutsche Telekom AG", Category: aupldb.CategoryISP, Country: "DE", RegisteredCountry: "DE"}},
			{Start: a("80.129.0.0")},
			// An Akamai range that also carries iCloud Private Relay.
			{Start: a("172.224.226.0"), Record: aupldb.Record{ASN: 36183, Name: "Akamai Technologies Inc.", Category: aupldb.CategoryHosting, Country: "US"}},
			{Start: a("172.224.227.0")},
		},
		[]aupldb.Entry{{Start: a("::")}},
		`{}`)
}

func TestNewFromLocalCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "asn.aupldb")
	if err := os.WriteFile(path, testDB(), 0o600); err != nil {
		t.Fatal(err)
	}
	dcFile := filepath.Join(dir, "dc.txt")
	os.WriteFile(dcFile, []byte("# hosting\nAS16509 Amazon\nas14061 DigitalOcean\nbogus\n"), 0o600)

	// No URL: the local copy alone must be enough to start.
	db, err := New(Options{PublicKeys: testKeys, Path: path}, []uint{64500}, []uint{64501}, []uint{15169}, dcFile)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := db.Lookup(net.ParseIP("8.8.8.8"))
	want := Record{ASN: 15169, Org: "Google LLC", Category: "hosting", Role: "midsize_transit", Country: "US", RegisteredCountry: "US",
		RIR: "arin", Allocated: "2023-12-28", RangeStart: "8.8.8.0", RangeEnd: "8.8.8.255", Datacenter: true}
	if err != nil || !reflect.DeepEqual(rec, want) {
		t.Errorf("Lookup(8.8.8.8) = %+v, %v\nwant %+v", rec, err, want)
	}
	if db.NameOf(15169) != "Google LLC" || db.CachedName(3320) != "Deutsche Telekom AG" || db.Info(3320).Category != "isp" {
		t.Errorf("names: %q %q %+v", db.NameOf(15169), db.CachedName(3320), db.Info(3320))
	}
	if rec, err := db.Lookup(net.ParseIP("10.0.0.1")); err != nil || rec.ASN != 0 {
		t.Errorf("Lookup(10.0.0.1) = %+v, %v; want unrouted", rec, err)
	}
	if _, err := db.Lookup(nil); err == nil {
		t.Error("Lookup(nil) succeeded")
	}
	for asn, want := range map[uint]bool{15169: true, 16509: true, 14061: true, 13335: false, 36183: false} {
		if db.IsDatacenter(asn) != want {
			t.Errorf("IsDatacenter(%d) = %v", asn, !want)
		}
	}
	if !db.IsBlocked(64500) || !db.IsAllowed(64501) || db.IsBlocked(64501) {
		t.Error("blocked/allowed lists not applied")
	}
}

func TestNewWithoutTokenRunsWithoutData(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	dir := t.TempDir()
	db, err := New(Options{PublicKeys: testKeys, Path: filepath.Join(dir, "asn.aupldb"), API: srv.URL, TokenFile: filepath.Join(dir, "token")}, nil, nil, nil, "")
	if err != nil {
		t.Fatalf("New without token or copy: %v", err)
	}
	if rec, err := db.Lookup(net.ParseIP("8.8.8.8")); err != nil || rec.ASN != 0 {
		t.Errorf("Lookup without data = %+v, %v; want unknown, no error", rec, err)
	}
	if !db.Status().NeedsToken {
		t.Error("Status doesn't ask for a token")
	}
	if hits != 0 {
		t.Errorf("%d requests without a token", hits)
	}
}

func TestNewDownloadsWithToken(t *testing.T) {
	file := testDB()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/asn.aupldb" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "missing or invalid token", http.StatusUnauthorized)
			return
		}
		w.Write(file)
	}))
	defer srv.Close()
	dir := t.TempDir()
	path, tokFile := filepath.Join(dir, "asn.aupldb"), filepath.Join(dir, "token")
	os.WriteFile(tokFile, []byte("tok\n"), 0o600)
	db, err := New(Options{PublicKeys: testKeys, Path: path, API: srv.URL + "/", TokenFile: tokFile}, nil, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if rec, _ := db.Lookup(net.ParseIP("8.8.8.8")); rec.ASN != 15169 {
		t.Errorf("Lookup after download = %+v", rec)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("download not saved: %v", err)
	}
	if st := db.Status(); st.SHA256 == "" || st.FetchedAt.IsZero() || st.NeedsToken {
		t.Errorf("Status = %+v", st)
	}
}

func TestTermsAndAccept(t *testing.T) {
	file := testDB()
	var registered map[string]string
	current := "2026-10-22"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/terms":
			json.NewEncoder(w).Encode(Terms{Version: current, Title: "T", Paragraphs: []string{"Be nice."}})
		case "POST /v1/tokens":
			json.NewDecoder(r.Body).Decode(&registered)
			if registered["accept"] != current {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{"error": "these are not the current terms", "version": current})
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"token": "aupla_edge_new", "class": "edge"})
		case "GET /v1/asn.aupldb":
			if r.Header.Get("Authorization") != "Bearer aupla_edge_new" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Write(file)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "sub", "token")
	db, err := New(Options{PublicKeys: testKeys, Path: filepath.Join(dir, "asn.aupldb"), API: srv.URL, TokenFile: tokFile}, nil, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	terms, err := db.Terms(context.Background())
	if err != nil || terms.Version != current || terms.Paragraphs[0] != "Be nice." {
		t.Fatalf("Terms = %+v, %v", terms, err)
	}
	if err := db.Accept(context.Background(), "2001-01-01", "loupe/test"); !errors.Is(err, ErrTermsChanged) {
		t.Errorf("Accept of old terms = %v, want ErrTermsChanged", err)
	}
	if err := db.Accept(context.Background(), current, "loupe/test"); err != nil {
		t.Fatal(err)
	}
	if registered["software"] != "loupe/test" || registered["instance"] == "" {
		t.Errorf("registration body = %v", registered)
	}
	raw, err := os.ReadFile(tokFile)
	if err != nil || string(raw) != "aupla_edge_new\n" {
		t.Fatalf("token file = %q, %v", raw, err)
	}
	if st, _ := os.Stat(tokFile); st.Mode().Perm() != 0o600 {
		t.Errorf("token file mode %v", st.Mode().Perm())
	}
	if db.Status().NeedsToken {
		t.Error("still needs a token after Accept")
	}
	// The new token works right away for downloads.
	if _, err := db.src.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec, _ := db.Lookup(net.ParseIP("8.8.8.8")); rec.ASN != 15169 {
		t.Errorf("Lookup after accepting = %+v", rec)
	}
}

// overlayDir seeds an overlay cache as an earlier run would have left it,
// for lists from the built-in manifest.
func overlayDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	lists := map[string][2]string{
		"tor_exits":           {"https://check.torproject.org/torbulkexitlist", "80.128.0.7\n"},
		"apple_private_relay": {"https://mask-api.icloud.com/egress-ip-ranges.csv", "172.224.226.0/27,GB,GB-EN,London,\n"},
		"linode":              {"https://geoip.linode.com/", "80.128.1.0/24,JP,JP-13,Tokyo,\n"},
		"googlebot": {"https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
			`{"prefixes": [{"ipv4Prefix": "8.8.8.8/32"}]}`},
	}
	for id, l := range lists {
		os.WriteFile(filepath.Join(dir, id+".list"), []byte(l[1]), 0o644)
		os.WriteFile(filepath.Join(dir, id+".json"), []byte(`{"url": "`+l[0]+`"}`), 0o644)
	}
	return dir
}

func TestLookupWithOverlay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "asn.aupldb")
	os.WriteFile(path, testDB(), 0o600)
	db, err := New(Options{PublicKeys: testKeys, Path: path, OverlayDir: overlayDir(t), DatacenterCategories: []string{"hosting"}}, nil, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip          string
		classes     string
		provider    string
		country     string
		datacenter  bool
		description string
	}{
		{"80.128.0.7", "tor_exit", "Tor", "DE", false, "a Tor exit on a residential network"},
		{"80.128.0.8", "", "", "DE", false, "residential"},
		{"80.128.1.1", "hosting", "Akamai Cloud (Linode)", "JP", true, "published cloud range in an ISP's space, with its geofeed country"},
		{"172.224.226.1", "relay", "iCloud Private Relay", "GB", false, "relay in hosting space: never a datacenter"},
		{"172.224.226.200", "", "", "US", true, "the rest of that hosting network"},
		{"8.8.8.8", "crawler", "Googlebot", "US", false, "verified crawler"},
		{"8.8.8.9", "", "", "US", true, "hosting by type"},
	}
	for _, c := range cases {
		rec, _ := db.Lookup(net.ParseIP(c.ip))
		if strings.Join(rec.Classes, ",") != c.classes || rec.Provider != c.provider || rec.Country != c.country || rec.Datacenter != c.datacenter {
			t.Errorf("%s (%s) = classes %v, provider %q, country %q, datacenter %v", c.ip, c.description, rec.Classes, rec.Provider, rec.Country, rec.Datacenter)
		}
	}
	if !db.IsDatacenter(36183) || db.IsDatacenter(3320) {
		t.Error("IsDatacenter by type")
	}
	if st := db.OverlayStatus(); len(st) < 30 {
		t.Errorf("overlay status: %d lists", len(st))
	}
	if _, err := New(Options{PublicKeys: testKeys, Path: path, DatacenterCategories: []string{"cloudz"}}, nil, nil, nil, ""); err == nil {
		t.Error("unknown network type accepted")
	}
	// Without categories, only listed networks are datacenters.
	plain, _ := New(Options{PublicKeys: testKeys, Path: path}, nil, nil, nil, "")
	if rec, _ := plain.Lookup(net.ParseIP("8.8.8.9")); rec.Datacenter || rec.Classes != nil {
		t.Errorf("no categories, no overlay: %+v", rec)
	}
}

func TestQueuedNamesArriveWithTheDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "asn.aupldb")
	var mu sync.Mutex
	got := map[uint]string{}
	db, err := New(Options{PublicKeys: testKeys, Path: path, OnName: func(a uint, n string) { mu.Lock(); got[a] = n; mu.Unlock() }}, nil, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	db.QueueNames([]uint{15169, 64999})
	if db.NameOf(3320) != "" || len(got) != 0 {
		t.Fatal("names without a database")
	}
	os.WriteFile(path, testDB(), 0o600)
	if err := db.src.Load(); err != nil {
		t.Fatal(err)
	}
	db.flushNames()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[15169] != "Google LLC" || got[3320] != "Deutsche Telekom AG" {
		t.Errorf("OnName got %v", got)
	}
}

// testKeys trusts aupldb.Build's test key.
var testKeys = []string{aupldb.FormatPublicKey(aupldb.TestPublicKeys[0])}
