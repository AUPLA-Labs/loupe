package badip

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const sample = `ip,lists
77.90.185.20,12
2.57.122.238,5
45.148.10.240,3
10.0.0.1,1
not-an-ip,4
1.2.3.4,zero
2001:db8::1,2
`

func TestParse(t *testing.T) {
	m, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 5 {
		t.Fatalf("parsed %d entries, want 5 (header and bad rows skipped): %v", len(m), m)
	}
	tsv, _ := Parse(strings.NewReader("ip\tlists\n9.9.9.9\t7\n"))
	if len(tsv) != 1 {
		t.Errorf("tab-separated: %v", tsv)
	}
}

func cachedFeed(t *testing.T, o Options) *Feed {
	t.Helper()
	o.CacheFile = filepath.Join(t.TempDir(), "badips.csv")
	if err := os.WriteFile(o.CacheFile, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	return New(o)
}

func TestCheckThresholds(t *testing.T) {
	f := cachedFeed(t, Options{ChallengeAt: 1, BlockAt: 5})
	cases := []struct {
		ip    string
		lists int
		act   Action
	}{
		{"77.90.185.20", 12, Block},
		{"2.57.122.238", 5, Block},
		{"45.148.10.240", 3, Challenge},
		{"10.0.0.1", 1, Challenge},
		{"8.8.8.8", 0, None},
		{"2001:db8::1", 2, Challenge},
		{"::ffff:45.148.10.240", 3, Challenge}, // IPv4-mapped form of a listed address
	}
	for _, c := range cases {
		n, act := f.Check(net.ParseIP(c.ip))
		if n != c.lists || act != c.act {
			t.Errorf("%s: (%d, %v), want (%d, %v)", c.ip, n, act, c.lists, c.act)
		}
	}

	high := cachedFeed(t, Options{ChallengeAt: 3, BlockAt: 0})
	if _, act := high.Check(net.ParseIP("10.0.0.1")); act != None {
		t.Errorf("below challenge_at: %v, want none", act)
	}
	if _, act := high.Check(net.ParseIP("77.90.185.20")); act != Challenge {
		t.Errorf("block_at 0 must never block: %v", act)
	}
}

func TestNilFeedIsDisabled(t *testing.T) {
	var f *Feed
	if n, act := f.Check(net.ParseIP("77.90.185.20")); n != 0 || act != None {
		t.Errorf("nil feed: (%d, %v)", n, act)
	}
	if st := f.Status(); st.Enabled {
		t.Error("nil feed reports enabled")
	}
	f.Run(context.Background()) // returns at once
}

func TestStatusHistogram(t *testing.T) {
	st := cachedFeed(t, Options{ChallengeAt: 2, BlockAt: 5}).Status()
	if st.Entries != 5 || len(st.Histogram) != 13 || st.Histogram[12] != 1 || st.Histogram[1] != 1 {
		t.Fatalf("status: %+v", st)
	}
	// 12 and 5 block; 3 and 2 challenge; 1 is below challenge_at.
	if st.Blocked != 2 || st.Challenged != 2 {
		t.Errorf("blocked %d challenged %d, want 2 and 2", st.Blocked, st.Challenged)
	}
}

func TestRefreshConditionalAndCached(t *testing.T) {
	var hits, notModified atomic.Int32
	body := "ip,lists\n5.5.5.5,4\n6.6.6.6,1\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("X-Ipsum-Upstream-Updated", "Tue, 20 Oct 2026 03:08:22 +0200")
		w.Write([]byte(body))
	}))
	defer srv.Close()

	cache := filepath.Join(t.TempDir(), "sub", "badips.csv")
	f := New(Options{URL: srv.URL, CacheFile: cache, BlockAt: 4})
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, act := f.Check(net.ParseIP("5.5.5.5")); act != Block {
		t.Errorf("after refresh: %v", act)
	}
	st := f.Status()
	if st.Upstream.IsZero() || st.Fetched.IsZero() || st.LastError != "" {
		t.Errorf("status after refresh: %+v", st)
	}
	if err := f.Refresh(context.Background()); err != nil || notModified.Load() != 1 {
		t.Fatalf("second refresh should be a 304: err=%v 304s=%d", err, notModified.Load())
	}

	// A restart loads the cached copy and its ETag without any request.
	before := hits.Load()
	g := New(Options{URL: srv.URL, CacheFile: cache, BlockAt: 4})
	if n := g.Lists(net.ParseIP("6.6.6.6")); n != 1 || hits.Load() != before {
		t.Errorf("from cache: lists=%d, requests %d→%d", n, before, hits.Load())
	}
	if g.snap.Load().etag != `"v1"` {
		t.Errorf("cached etag = %q", g.snap.Load().etag)
	}
}

func TestRefreshFailureKeepsList(t *testing.T) {
	fail := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case fail.Load():
			w.Write([]byte("ip,lists\n")) // empty list
		default:
			w.Write([]byte("ip,lists\n5.5.5.5,2\n"))
		}
	}))
	defer srv.Close()
	f := New(Options{URL: srv.URL})
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := f.Refresh(context.Background()); err == nil {
		t.Fatal("an empty list must be rejected")
	}
	if f.Lists(net.ParseIP("5.5.5.5")) != 2 {
		t.Error("previous list lost after a failed refresh")
	}
	if f.Status().LastError == "" {
		t.Error("failure not reported in status")
	}
}
