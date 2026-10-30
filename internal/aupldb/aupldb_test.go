package aupldb

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	google = Record{ASN: 15169, Country: "US", RIR: 1, Allocated: 20231228, Name: "Google LLC"}
	cf     = Record{ASN: 13335, Country: "AU", RIR: 3, Flags: 1, Name: "Cloudflare, Inc."}
	edge   = Record{ASN: 64500} // no name, as in the edge file
)

// testBuiltAt is recent, so the Updater's maximum age doesn't reject it.
var testBuiltAt = time.Now().Add(-time.Hour).Truncate(time.Second)

func testFile(t *testing.T) []byte {
	t.Helper()
	a := netip.MustParseAddr
	return Build(testBuiltAt,
		[]Entry{
			{a("0.0.0.0"), Record{}},
			{a("1.1.1.0"), cf},
			{a("1.1.2.0"), Record{}},
			{a("8.8.8.0"), google},
			{a("8.8.9.0"), edge},
			{a("8.8.10.0"), Record{}},
		},
		[]Entry{
			{a("::"), Record{}},
			{a("2a00:1450::"), google},
			{a("2a00:1451::"), Record{}},
		},
		`{"format":"aupldb","sources":[]}`)
}

func TestLookup(t *testing.T) {
	db, err := Parse(testFile(t))
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]Record{
		"0.0.0.1":              {},
		"1.1.1.0":              cf,
		"1.1.1.255":            cf,
		"1.1.2.0":              {},
		"8.8.8.8":              google,
		"8.8.9.1":              edge,
		"::ffff:8.8.8.8":       google,
		"255.255.255.255":      {},
		"2a00:1450::1":         google,
		"2a00:1450:ffff::":     google,
		"2a00:1451::":          {},
		"ffff:ffff:ffff::ffff": {},
	} {
		got, _, ok := db.Lookup(netip.MustParseAddr(ip))
		if !ok || got != want {
			t.Errorf("Lookup(%s) = %+v, %v; want %+v", ip, got, ok, want)
		}
	}
	if _, _, ok := db.Lookup(netip.Addr{}); ok {
		t.Error("Lookup of the zero Addr succeeded")
	}
	if db.BuiltAt.Unix() != testBuiltAt.Unix() {
		t.Errorf("BuiltAt = %v", db.BuiltAt)
	}
}

func TestParseRejectsDamage(t *testing.T) {
	good := testFile(t)
	cases := map[string]func([]byte) []byte{
		"short":     func(b []byte) []byte { return b[:40] },
		"magic":     func(b []byte) []byte { b[0] = 'X'; return b },
		"version":   func(b []byte) []byte { b[6] = 2; return b },
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
		"checksum":  func(b []byte) []byte { b[70] ^= 1; return b },
	}
	for name, damage := range cases {
		b := damage(append([]byte(nil), good...))
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: Parse accepted a damaged file", name)
		}
	}
}

func TestParseRejectsUnsortedTable(t *testing.T) {
	a := netip.MustParseAddr
	b := Build(time.Now(),
		[]Entry{{a("0.0.0.0"), Record{}}, {a("8.0.0.0"), cf}, {a("9.0.0.0"), google}},
		[]Entry{{a("::"), Record{}}}, `{}`)
	// Move the second start past the third, and re-sign the body so only the
	// order check can catch it.
	v4k := binary.LittleEndian.Uint64(b[headerSize+8:]) // V4KY is the first section
	binary.LittleEndian.PutUint32(b[v4k+4:], 0x0a000000)
	sum := sha256.Sum256(b[:len(b)-footerSize])
	copy(b[len(b)-footerSize:], sum[:])
	if _, err := Parse(b); err == nil || !strings.Contains(err.Error(), "out of order") {
		t.Errorf("Parse = %v, want out of order", err)
	}
}

func TestUpdater(t *testing.T) {
	file := testFile(t)
	db, _ := Parse(file)
	var hits, notModified atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "missing or invalid token", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("If-None-Match") == `"`+db.SHA256+`"` {
			notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Write(file)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "asn.aupldb")
	u := &Updater{URL: srv.URL, Path: path, PublicKeys: TestPublicKeys}
	if _, err := u.Refresh(context.Background()); !errors.Is(err, ErrNoToken) || !u.NeedsToken() {
		t.Fatalf("Refresh without a token = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("downloaded without a token")
	}
	u.SetToken("tok")
	if err := u.Load(); err == nil {
		t.Fatal("Load of a missing file succeeded")
	}
	if changed, err := u.Refresh(context.Background()); err != nil || !changed {
		t.Fatalf("first Refresh = %v, %v", changed, err)
	}
	if rec, _, _ := u.DB().Lookup(netip.MustParseAddr("8.8.8.8")); rec != google {
		t.Errorf("lookup after refresh = %+v", rec)
	}
	if changed, err := u.Refresh(context.Background()); err != nil || changed || notModified.Load() != 1 {
		t.Fatalf("second Refresh = %v, %v (304s: %d)", changed, err, notModified.Load())
	}

	// The saved copy carries a restart.
	u2 := &Updater{URL: srv.URL, Path: path, PublicKeys: TestPublicKeys}
	if err := u2.Load(); err != nil {
		t.Fatal(err)
	}
	if u2.DB().SHA256 != db.SHA256 {
		t.Error("reloaded copy differs")
	}

	// A bad token is an error and keeps the current copy.
	u2.SetToken("wrong")
	if _, err := u2.Refresh(context.Background()); !errors.Is(err, ErrUnauthorized) || !u2.NeedsToken() {
		t.Errorf("Refresh with a bad token = %v, NeedsToken %v", err, u2.NeedsToken())
	}
	if st := u2.Status(); !st.NeedsToken || st.LastError == "" || st.SHA256 != db.SHA256 {
		t.Errorf("Status after a 401 = %+v", st)
	}
	u2.SetToken("tok") // a new token clears both
	if st := u2.Status(); u2.NeedsToken() || st.NeedsToken || st.LastError != "" {
		t.Errorf("Status after SetToken = %+v", st)
	}
}

func TestUpdaterKeepsCopyOnCorruptDownload(t *testing.T) {
	file := testFile(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(file[:len(file)-3])
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "asn.aupldb")
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatal(err)
	}
	u := &Updater{URL: srv.URL, Path: path, PublicKeys: TestPublicKeys}
	u.SetToken("tok")
	if err := u.Load(); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Refresh(context.Background()); err == nil || errors.Is(err, ErrNoToken) {
		t.Fatalf("corrupt download: %v", err)
	}
	if got, _ := os.ReadFile(path); len(got) != len(file) {
		t.Error("local copy was overwritten")
	}
}

// TestUpdaterTrust: files must be signed by a trusted key, and one that is
// too old is not used, though the dashboard still shows it.
func TestUpdaterTrust(t *testing.T) {
	file := testFile(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(file) }))
	defer srv.Close()
	u := &Updater{URL: srv.URL}
	u.SetToken("tok")
	if _, err := u.Refresh(context.Background()); !errors.Is(err, ErrNoKeys) {
		t.Errorf("Refresh without keys = %v", err)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	u.PublicKeys = []ed25519.PublicKey{other.Public().(ed25519.PublicKey)}
	if _, err := u.Refresh(context.Background()); !errors.Is(err, ErrUnknownKey) || u.DB() != nil {
		t.Errorf("Refresh with another key = %v", err)
	}
	u.PublicKeys = TestPublicKeys
	if changed, err := u.Refresh(context.Background()); err != nil || !changed {
		t.Fatalf("Refresh = %v %v", changed, err)
	}
	u.now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	if u.DB() != nil {
		t.Error("a file older than MaxAge is still used")
	}
	if st := u.Status(); st.SHA256 == "" || !strings.Contains(st.LastError, "older than") {
		t.Errorf("Status of a stale file = %+v", st)
	}
}
