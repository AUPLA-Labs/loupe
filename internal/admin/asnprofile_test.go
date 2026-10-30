package admin

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/asn"
	"github.com/AUPLA-Labs/loupe/internal/aupldb"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
)

func TestASNProfile(t *testing.T) {
	s := newTestStore(t, 100)
	t0 := time.Now().Add(-time.Hour)
	s.Add(Event{Time: t0, Action: "CHALLENGE", IP: "192.0.2.1", ASN: 64500, Org: "Example Net"})
	s.Add(Event{Time: t0.Add(time.Minute), Action: "BLOCK", IP: "192.0.2.2", ASN: 64500})
	s.Add(Event{Time: t0.Add(2 * time.Minute), Action: "BLOCK", IP: "192.0.2.2", ASN: 64500})
	s.Add(Event{Time: t0.Add(3 * time.Minute), Action: "ALLOW", IP: "198.51.100.1", ASN: 64501})

	p := s.ASNProfile(64500)
	if p.Total != 3 || p.ByAction["BLOCK"] != 2 || p.Org != "Example Net" || p.IPCount != 2 {
		t.Fatalf("profile = %+v", p)
	}
	if len(p.IPs) != 2 || p.IPs[0].IP != "192.0.2.2" || p.IPs[0].Count != 2 || p.IPs[0].Blocked != 2 {
		t.Fatalf("ips = %+v", p.IPs)
	}
	if !p.IPs[0].Last.Equal(t0.Add(2 * time.Minute)) {
		t.Errorf("last = %v", p.IPs[0].Last)
	}
	if !p.First.Equal(t0) || len(p.Events) != 3 || p.Events[0].Action != "CHALLENGE" {
		t.Errorf("first = %v, events = %+v", p.First, p.Events)
	}
}

// fakeASN is an ASNSource whose names are all already resolved: looking one
// up that isn't there must never be how a name is found.
type fakeASN struct {
	names map[uint]string
	dc    map[uint]bool
}

func (f fakeASN) Status() aupldb.Status                        { return aupldb.Status{} }
func (f fakeASN) Terms(context.Context) (asn.Terms, error)     { return asn.Terms{}, nil }
func (f fakeASN) Accept(context.Context, string, string) error { return nil }
func (f fakeASN) CachedName(a uint) string                     { return f.names[a] }
func (f fakeASN) IsDatacenter(a uint) bool                     { return f.dc[a] }
func (f fakeASN) IsBlocked(a uint) bool                        { return a == 64666 }
func (f fakeASN) IsAllowed(uint) bool                          { return false }
func (f fakeASN) OverlayStatus() []aupldb.ListStatus           { return nil }
func (f fakeASN) Info(a uint) asn.ASNInfo                      { return asn.ASNInfo{Name: f.names[a]} }
func (f fakeASN) Lookup(ip net.IP) (asn.Record, error) {
	if ip.Equal(net.ParseIP("192.0.2.1")) {
		return asn.Record{ASN: 64500, Org: "Buffered Net", Country: "NL", Category: "hosting", Classes: []string{"vpn"}, Provider: "SomeVPN", Datacenter: true}, nil
	}
	return asn.Record{}, nil
}

func TestASNEndpointAndPressureNames(t *testing.T) {
	store := newTestStore(t, 100)
	store.Add(Event{Time: time.Now(), Action: "BLOCK", IP: "192.0.2.1", ASN: 64500, Org: "Buffered Net"})
	rep := reputation.New(reputation.Config{NonDatacenterMultiplier: 3})
	rep.Record("192.0.2.1", 64500, reputation.Webdriver)
	rep.Record("203.0.113.9", 64501, reputation.Webdriver)
	rep.Record("203.0.113.10", 64502, reputation.Webdriver)
	srv := NewServer(store, rep, "", AuthOptions{})
	srv.SetASN(fakeASN{names: map[uint]string{64501: "Cached Net"}, dc: map[uint]bool{64501: true}})
	h := srv.Handler()

	get := func(url string, v any) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		if w.Code == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
				t.Fatal(err)
			}
		}
		return w.Code
	}

	var p struct {
		ASN        uint               `json:"asn"`
		Org        string             `json:"org"`
		IPCount    int                `json:"ip_count"`
		IPs        []ASNClient        `json:"ips"`
		Pressure   float64            `json:"pressure"`
		Floors     map[string]float64 `json:"floors"`
		IPFloors   map[string]float64 `json:"ip_floors"`
		Datacenter bool               `json:"datacenter"`
	}
	if code := get("/api/asn?asn=AS64500", &p); code != http.StatusOK {
		t.Fatalf("GET /api/asn = %d", code)
	}
	if p.ASN != 64500 || p.Org != "Buffered Net" || p.IPCount != 1 || p.IPs[0].Pressure <= 0 || p.Pressure <= 0 {
		t.Fatalf("profile = %+v", p)
	}
	if p.Datacenter || p.Floors["prism"] != 3*p.IPFloors["prism"] {
		t.Errorf("residential network floors = %v, ip floors = %v", p.Floors, p.IPFloors)
	}
	p.Org = ""
	if get("/api/asn?asn=64501", &p); p.Org != "Cached Net" || !p.Datacenter || p.Floors["prism"] != p.IPFloors["prism"] {
		t.Errorf("cached-name datacenter profile = %+v", p)
	}
	if code := get("/api/asn?asn=x", &p); code != http.StatusBadRequest {
		t.Errorf("bad asn = %d, want 400", code)
	}

	var pr struct {
		Entries []pressureRow `json:"entries"`
	}
	get("/api/pressure", &pr)
	names := map[string]string{}
	for _, e := range pr.Entries {
		if e.Kind == "asn" {
			names[e.Key] = e.Name
		}
	}
	want := map[string]string{"AS64500": "Buffered Net", "AS64501": "Cached Net", "AS64502": ""}
	for k, v := range want {
		if n, ok := names[k]; !ok || n != v {
			t.Errorf("pressure name of %s = %q (present %v), want %q", k, n, ok, v)
		}
	}
}

func TestNetworkInvestigationData(t *testing.T) {
	store := newTestStore(t, 100)
	now := time.Now()
	store.Add(Event{Time: now, Action: "CHALLENGE", IP: "192.0.2.1", ASN: 64500, Country: "NL", NetType: "hosting", Classes: []string{"vpn", "hosting"}, Provider: "SomeVPN"})
	store.Add(Event{Time: now, Action: "BLOCK", IP: "192.0.2.2", ASN: 64500, Country: "NL", NetType: "hosting", Classes: []string{"tor_exit"}})
	store.Add(Event{Time: now, Action: "ALLOW", IP: "198.51.100.1", ASN: 64501, Country: "DE", NetType: "isp"})
	srv := NewServer(store, reputation.New(reputation.Config{}), "", AuthOptions{})
	srv.SetASN(fakeASN{names: map[uint]string{64500: "Buffered Net"}})
	h := srv.Handler()
	get := func(url string, v any) {
		t.Helper()
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", url, w.Code)
		}
		json.Unmarshal(w.Body.Bytes(), v)
	}

	var ip IPProfile
	get("/api/ip?ip=192.0.2.1", &ip)
	if n := ip.Network; n == nil || n.Country != "NL" || n.Provider != "SomeVPN" || !n.Datacenter || n.Classes[0] != "vpn" {
		t.Errorf("ip network = %+v", ip.Network)
	}
	var as struct {
		Info *asn.ASNInfo `json:"info"`
	}
	get("/api/asn?asn=64500", &as)
	if as.Info == nil || as.Info.Name != "Buffered Net" {
		t.Errorf("asn info = %+v", as.Info)
	}

	st := store.Stats()
	if len(st.TopCountries) != 2 || st.TopCountries[0].Key != "NL" || st.TopCountries[0].Count != 2 {
		t.Errorf("top countries = %+v", st.TopCountries)
	}
	if len(st.TopClasses) != 3 || len(st.TopNetTypes) != 2 || st.TopNetTypes[0].Key != "hosting" {
		t.Errorf("top classes = %+v, types = %+v", st.TopClasses, st.TopNetTypes)
	}

	var evs struct{ Events []Event }
	get("/api/events?class=tor_exit", &evs)
	if len(evs.Events) != 1 || evs.Events[0].IP != "192.0.2.2" {
		t.Errorf("class filter = %+v", evs.Events)
	}
	get("/api/events?country=de", &evs)
	if len(evs.Events) != 1 || evs.Events[0].IP != "198.51.100.1" {
		t.Errorf("country filter = %+v", evs.Events)
	}
	get("/api/events?q=somevpn", &evs)
	if len(evs.Events) != 1 {
		t.Errorf("search by provider = %+v", evs.Events)
	}
}
