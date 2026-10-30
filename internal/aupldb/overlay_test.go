package aupldb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDefaultSources(t *testing.T) {
	var raw struct{ Sources []json.RawMessage }
	if err := json.Unmarshal(DefaultSources(), &raw); err != nil {
		t.Fatal(err)
	}
	m, err := ParseManifest(DefaultSources())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Sources) != len(raw.Sources) || len(m.Sources) < 30 {
		t.Errorf("kept %d of %d built-in sources", len(m.Sources), len(raw.Sources))
	}
}

func TestParseManifestDrops(t *testing.T) {
	m, err := ParseManifest([]byte(`{"version": 1, "sources": [
		{"id": "ok", "class": "vpn", "url": "https://a/", "parser": "lines"},
		{"id": "ok", "class": "vpn", "url": "https://dup/", "parser": "lines"},
		{"id": "newclass", "class": "satellite", "url": "https://a/", "parser": "lines"},
		{"id": "newparser", "class": "vpn", "url": "https://a/", "parser": "yaml"},
		{"id": "nokeys", "class": "vpn", "url": "https://a/", "parser": "json"},
		{"id": "badre", "class": "vpn", "url": "https://a/", "parser": "regex", "pattern": "("},
		{"id": "../etc", "class": "vpn", "url": "https://a/", "parser": "lines"},
		{"id": "plain", "class": "vpn", "url": "http://a/", "parser": "lines"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Sources) != 1 || m.Sources[0].URL != "https://a/" || m.Sources[0].CadenceHours != 24 {
		t.Errorf("sources = %+v", m.Sources)
	}
	if _, err := ParseManifest([]byte(`{"version": 2, "sources": []}`)); err == nil {
		t.Error("accepted manifest version 2")
	}
}

func TestParseList(t *testing.T) {
	cases := []struct {
		src  Source
		body string
		want []string // prefix or prefix=country
	}{
		{Source{Parser: "lines"}, "# exits\n185.220.101.1\n\n2a0b:f4c2::1\n10.0.0.1\n,\n", []string{"185.220.101.1/32", "2a0b:f4c2::1/128"}},
		{Source{Parser: "lines"}, "173.245.48.0/20\n0.0.0.0/0\n1.0.0.0/7\n", []string{"173.245.48.0/20"}},
		{Source{Parser: "geofeed"}, "# ip_prefix,alpha2code,region\n172.224.226.0/27,GB,GB-EN,London,\n2600:3c00::/32,us,US-TX\n5.0.0.0/24,,\n",
			[]string{"172.224.226.0/27=GB", "2600:3c00::/32=US", "5.0.0.0/24"}},
		{Source{Parser: "json", Keys: []string{"ipv4Prefix", "ips"}},
			`{"prefixes": [{"ipv4Prefix": "66.249.64.0/27"}, {"other": "1.2.3.4"}], "x": {"ips": ["9.9.9.9", 5]}}` + "\nSIGNATURE==",
			[]string{"66.249.64.0/27", "9.9.9.9/32"}},
		{Source{Parser: "regex", Pattern: `\sip="([^"]+)"`}, `<s name="a" ip="207.204.228.28" /><s ip="nope"/><s vip="1.1.1.1"/>`, []string{"207.204.228.28/32"}},
	}
	for _, c := range cases {
		got, err := parseList(c.src, []byte(c.body))
		if err != nil {
			t.Errorf("%s: %v", c.src.Parser, err)
			continue
		}
		var s []string
		for _, g := range got {
			v := g.p.String()
			if g.country != "" {
				v += "=" + g.country
			}
			s = append(s, v)
		}
		// The JSON walk visits map keys in random order; the index sorts later.
		slices.Sort(s)
		slices.Sort(c.want)
		if strings.Join(s, " ") != strings.Join(c.want, " ") {
			t.Errorf("%s: got %v, want %v", c.src.Parser, s, c.want)
		}
	}
	if _, err := parseList(Source{Parser: "lines"}, []byte("<html>maintenance</html>\n")); err == nil {
		t.Error("a list without addresses was accepted")
	}
	if _, err := parseList(Source{Parser: "json", Keys: []string{"ip"}}, []byte("{")); err == nil {
		t.Error("broken JSON was accepted")
	}
}

// fakePublishers serves a manifest and lists over TLS, counting requests and
// answering If-None-Match like a real publisher would.
type fakePublishers struct {
	mu    sync.Mutex
	files map[string]string
	fail  map[string]bool
	hits  map[string]int
}

func (f *fakePublishers) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits[r.URL.Path]++
	if f.fail[r.URL.Path] {
		http.Error(w, "down", http.StatusBadGateway)
		return
	}
	body, ok := f.files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	etag := `"` + string(rune('a'+len(body)%26)) + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write([]byte(body))
}

func (f *fakePublishers) set(path, body string, fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path], f.fail[path] = body, fail
}

func (f *fakePublishers) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func TestOverlay(t *testing.T) {
	pub := &fakePublishers{files: map[string]string{}, fail: map[string]bool{}, hits: map[string]int{}}
	srv := httptest.NewTLSServer(pub)
	defer srv.Close()
	manifest := func(ids ...string) string {
		all := map[string]string{
			"tor":   `{"id": "tor", "class": "tor_exit", "provider": "Tor", "url": "` + srv.URL + `/tor", "parser": "lines", "cadence_hours": 1}`,
			"vpn":   `{"id": "vpn", "class": "vpn", "provider": "SomeVPN", "url": "` + srv.URL + `/vpn", "parser": "json", "keys": ["ip"]}`,
			"cloud": `{"id": "cloud", "class": "hosting", "provider": "SomeCloud", "url": "` + srv.URL + `/cloud", "parser": "geofeed"}`,
		}
		var parts []string
		for _, id := range ids {
			parts = append(parts, all[id])
		}
		return `{"version": 1, "sources": [` + strings.Join(parts, ",") + `]}`
	}
	pub.set("/manifest", manifest("tor", "vpn", "cloud"), false)
	pub.set("/tor", "185.220.101.1\n185.220.101.2\n", false)
	pub.set("/vpn", `{"servers": [{"ip": "203.0.113.200"}, {"ip": "198.51.100.7"}]}`, false)
	pub.set("/cloud", "203.0.113.0/24,DE,DE-HE,Frankfurt\n2001:db8:1::/48,NL\n", false)

	dir := t.TempDir()
	newOverlay := func() *Overlay {
		return &Overlay{ManifestURL: srv.URL + "/manifest", Dir: dir, Client: srv.Client()}
	}
	ov := newOverlay()
	if h := ov.Lookup(netip.MustParseAddr("185.220.101.1")); h != (Hit{}) {
		t.Errorf("hit before any data: %+v", h)
	}
	if err := ov.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	check := func(ov *Overlay, ip string, want Hit) {
		t.Helper()
		if got := ov.Lookup(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Lookup(%s) = %+v, want %+v", ip, got, want)
		}
	}
	check(ov, "185.220.101.2", Hit{Classes: ClassTorExit, Provider: "Tor", List: "tor"})
	check(ov, "185.220.101.3", Hit{})
	check(ov, "::ffff:185.220.101.1", Hit{Classes: ClassTorExit, Provider: "Tor", List: "tor"})
	// In a VPN list and a cloud range: both classes, the VPN named, the cloud's country.
	check(ov, "203.0.113.200", Hit{Classes: ClassVPN | ClassHosting, Provider: "SomeVPN", List: "vpn", Country: "DE"})
	check(ov, "203.0.113.201", Hit{Classes: ClassHosting, Provider: "SomeCloud", List: "cloud", Country: "DE"})
	check(ov, "2001:db8:1:ffff::1", Hit{Classes: ClassHosting, Provider: "SomeCloud", List: "cloud", Country: "NL"})
	if names := (ClassVPN | ClassHosting).Names(); strings.Join(names, ",") != "vpn,hosting" {
		t.Errorf("names = %v", names)
	}

	// Nothing is due yet: no requests.
	before := pub.count("/tor")
	if err := ov.Refresh(t.Context()); err != nil || pub.count("/tor") != before {
		t.Errorf("refresh fetched again: %v, %d requests", err, pub.count("/tor")-before)
	}

	// Due again: unchanged lists cost a 304; a broken or empty list keeps its old copy.
	pub.set("/vpn", `{"servers": []}`, false)
	pub.set("/cloud", "", true)
	for _, l := range ov.lists {
		l.meta.FetchedAt = time.Now().Add(-200 * time.Hour)
	}
	if err := ov.Refresh(t.Context()); err == nil || !strings.Contains(err.Error(), "vpn") || !strings.Contains(err.Error(), "cloud") {
		t.Errorf("refresh error = %v", err)
	}
	check(ov, "203.0.113.200", Hit{Classes: ClassVPN | ClassHosting, Provider: "SomeVPN", List: "vpn", Country: "DE"})
	if st := ov.Status(); len(st) != 3 || st[0].Prefixes != 2 || st[1].Error == "" {
		t.Errorf("status = %+v", st)
	}

	// A new process starts from the cache, without the network.
	srvURL := srv.URL
	cold := &Overlay{ManifestURL: srvURL + "/manifest", Dir: dir}
	if err := cold.Load(); err != nil {
		t.Fatal(err)
	}
	check(cold, "185.220.101.1", Hit{Classes: ClassTorExit, Provider: "Tor", List: "tor"})
	check(cold, "203.0.113.200", Hit{Classes: ClassVPN | ClassHosting, Provider: "SomeVPN", List: "vpn", Country: "DE"})

	// A source dropped from the manifest goes away once the manifest is rechecked.
	pub.set("/manifest", manifest("tor"), false)
	ov.manifest = nil
	writeAtomic(dir+"/manifest.meta.json", []byte(`{}`))
	if err := ov.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	check(ov, "203.0.113.200", Hit{})
	check(ov, "185.220.101.1", Hit{Classes: ClassTorExit, Provider: "Tor", List: "tor"})
}

func TestOverlayBuiltInManifest(t *testing.T) {
	ov := &Overlay{Dir: t.TempDir()}
	if err := ov.Load(); err != nil {
		t.Fatal(err)
	}
	if st := ov.Status(); len(st) < 30 || st[0].ID != "tor_exits" {
		t.Errorf("status = %d lists", len(st))
	}
	if h := ov.Lookup(netip.MustParseAddr("1.1.1.1")); h != (Hit{}) {
		t.Errorf("hit without data: %+v", h)
	}
}
