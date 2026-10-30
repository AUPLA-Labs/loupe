package asn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// dcFixture serves body (set per step) with an ETag, and builds a DB whose
// datacenter list comes from it. ASN 65000 is listed in config.
func dcFixture(t *testing.T, serve func(w http.ResponseWriter, r *http.Request)) (*DB, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(serve))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	file := filepath.Join(dir, "datacenter_asns.txt")
	d, err := New(Options{Path: filepath.Join(dir, "asn.aupldb"), DatacenterListURL: srv.URL}, nil, nil, []uint{65000}, file)
	if err != nil {
		t.Fatal(err)
	}
	return d, file
}

func TestDatacenterRefreshSwapsList(t *testing.T) {
	d, file := dcFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("AS64500 Some Host\n64501\n"))
	})
	if d.IsDatacenter(64500) {
		t.Fatal("64500 listed before any fetch")
	}
	if err := d.refreshDatacenterList(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, n := range []uint{64500, 64501, 65000} {
		if !d.IsDatacenter(n) {
			t.Errorf("IsDatacenter(%d) = false", n)
		}
	}
	if got, _ := os.ReadFile(file); string(got) != "AS64500 Some Host\n64501\n" {
		t.Errorf("file = %q", got)
	}
}

func TestDatacenterRefreshKeepsListOnBadFetch(t *testing.T) {
	var step atomic.Int32
	d, file := dcFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch step.Load() {
		case 0:
			w.Write([]byte("AS64500\n"))
		case 1:
			http.Error(w, "boom", http.StatusInternalServerError)
		case 2:
			w.Write([]byte("<html><body>Not here</body></html>\n"))
		default:
			// empty 200
		}
	})
	if err := d.refreshDatacenterList(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := int32(1); i <= 3; i++ {
		step.Store(i)
		if err := d.refreshDatacenterList(context.Background()); err == nil {
			t.Errorf("step %d: no error", i)
		}
		if !d.IsDatacenter(64500) {
			t.Errorf("step %d: list lost in memory", i)
		}
		if got, _ := os.ReadFile(file); string(got) != "AS64500\n" {
			t.Errorf("step %d: file = %q", i, got)
		}
	}
}

func TestDatacenterRefreshConditional(t *testing.T) {
	var sawETag atomic.Value
	var calls atomic.Int32
	d, _ := dcFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 1 {
			sawETag.Store(r.Header.Get("If-None-Match"))
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte("AS64500\n"))
	})
	for range 2 {
		if err := d.refreshDatacenterList(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := sawETag.Load(); got != `"v1"` {
		t.Errorf("If-None-Match = %v, want \"v1\"", got)
	}
	if !d.IsDatacenter(64500) {
		t.Error("304 dropped the list")
	}
}

// A configured file that doesn't exist yet is fine when a URL will fill it,
// and still an error when nothing will.
func TestDatacenterMissingFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "missing.txt")
	if _, err := New(Options{Path: filepath.Join(dir, "a"), DatacenterListURL: "http://127.0.0.1:1/"}, nil, nil, nil, file); err != nil {
		t.Errorf("with URL: %v", err)
	}
	if _, err := New(Options{Path: filepath.Join(dir, "a")}, nil, nil, nil, file); err == nil {
		t.Error("without URL: no error")
	}
}
