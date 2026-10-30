package reputation

import (
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

func testConfig() Config {
	return Config{
		HalfLife:                6 * time.Hour,
		Floors:                  Floors{Tier2: 4, Tier3: 12, Tier4: 40},
		NonDatacenterMultiplier: 4,
	}
}

func TestUnknownKeyHasNoFloor(t *testing.T) {
	s := New(testConfig())
	if got := s.Floor("1.2.3.4", 12345, true); got != tier.Pass {
		t.Fatalf("unknown key should have no floor, got %v", got)
	}
}

func TestRecordRaisesIPFloor(t *testing.T) {
	s := New(testConfig())
	s.Record("1.2.3.4", 0, Webdriver) // +10, unconditional per-IP
	// 10 is between Tier2 (4) and Tier3 (12), so it floors at LumenAuto —
	// TestFloorTable below covers the full threshold table in isolation.
	if got := s.Floor("1.2.3.4", 0, false); got != tier.LumenAuto {
		t.Fatalf("pressure 10 should floor at LumenAuto, got %v", got)
	}
}

func TestFloorTable(t *testing.T) {
	cases := []struct {
		name      string
		pressure  float64
		wantFloor tier.Tier
	}{
		{"below tier2", 3.9, tier.Pass},
		{"at tier2", 4, tier.LumenAuto},
		{"between tier2 and tier3", 11.9, tier.LumenAuto},
		{"at tier3", 12, tier.SingleClick},
		{"between tier3 and tier4", 39.9, tier.SingleClick},
		{"at tier4", 40, tier.Prism},
		{"well above tier4", 1000, tier.Prism},
	}
	for _, c := range cases {
		if got := floorFor(c.pressure, testConfig().Floors); got != c.wantFloor {
			t.Errorf("%s: floorFor(%v) = %v, want %v", c.name, c.pressure, got, c.wantFloor)
		}
	}
}

func TestPerIPPressureIsUnconditional(t *testing.T) {
	// A residential (non-datacenter) IP with high enough pressure must still
	// reach Prism — only the ASN aggregate is capped, never the IP itself.
	s := New(testConfig())
	for i := 0; i < 5; i++ {
		s.Record("9.9.9.9", 0, Webdriver) // 5*10 = 50, well past tier4 (40)
	}
	if got := s.Floor("9.9.9.9", 0, false); got != tier.Prism {
		t.Fatalf("unconditional per-IP pressure should reach Prism, got %v", got)
	}
}

func TestNonDatacenterASNCappedAtSingleClick(t *testing.T) {
	s := New(testConfig())
	// Push ASN pressure far past what even the 4x-scaled tier4 threshold
	// (40*4=160) would require, using a key with zero per-IP pressure.
	for i := 0; i < 30; i++ {
		s.Record("1.1.1."+string(rune('0'+i%10)), 6461, Webdriver) // 30*10 = 300
	}
	if got := s.Floor("255.255.255.255", 6461, false); got != tier.SingleClick {
		t.Fatalf("non-datacenter ASN at pressure 100+ must cap at SingleClick, got %v", got)
	}
}

func TestDatacenterASNReachesPrism(t *testing.T) {
	s := New(testConfig())
	for i := 0; i < 5; i++ {
		s.Record("2.2.2."+string(rune('0'+i)), 16509, Webdriver) // 5*10 = 50
	}
	if got := s.Floor("255.255.255.255", 16509, true); got != tier.Prism {
		t.Fatalf("datacenter ASN pressure 50 should reach Prism, got %v", got)
	}
}

func TestCleanPassHalves(t *testing.T) {
	s := New(testConfig())
	s.Record("3.3.3.3", 0, Webdriver) // +10
	before := s.IPPressure("3.3.3.3")
	s.Record("3.3.3.3", 0, CleanPass)
	after := s.IPPressure("3.3.3.3")
	if after > before/2+0.01 || after < before/2-0.01 {
		t.Fatalf("clean pass should halve pressure: before=%v after=%v want~%v", before, after, before/2)
	}
}

func TestDecayAcrossHalfLifeBoundary(t *testing.T) {
	s := New(testConfig())
	s.Record("4.4.4.4", 0, Webdriver) // +10
	// Manually rewind the internal timestamp by exactly one half-life to
	// simulate elapsed time without sleeping in a test.
	s.mu.Lock()
	s.ip["4.4.4.4"].LastUpdate = time.Now().Add(-6 * time.Hour)
	s.mu.Unlock()
	got := s.IPPressure("4.4.4.4")
	if got > 5.1 || got < 4.9 {
		t.Fatalf("pressure should have halved after one half-life: got %v, want ~5", got)
	}
}

func TestHighRequestScoreEventIncrementIsTwo(t *testing.T) {
	s := New(testConfig())
	s.Record("5.5.5.5", 0, HighRequestScore)
	if got := s.IPPressure("5.5.5.5"); got != 2 {
		t.Fatalf("HighRequestScore increment = %v, want 2", got)
	}
}

func TestZeroASNIsNeverRecorded(t *testing.T) {
	// asn=0 means "unresolved" — recording pressure under that key would
	// pollute a meaningless shared bucket across every unresolved lookup.
	s := New(testConfig())
	s.Record("6.6.6.6", 0, Webdriver)
	if got := s.ASNPressure(0); got != 0 {
		t.Fatalf("ASN 0 should never accumulate pressure, got %v", got)
	}
}

func TestTopPressuredSortsDescending(t *testing.T) {
	s := New(testConfig())
	s.Record("1.1.1.1", 0, Webdriver) // 10
	s.Record("2.2.2.2", 0, Webdriver)
	s.Record("2.2.2.2", 0, Webdriver) // 20
	top := s.TopPressured(10)
	if len(top) < 2 {
		t.Fatalf("expected at least 2 entries, got %d", len(top))
	}
	if top[0].Key != "2.2.2.2" || top[0].Pressure < top[1].Pressure {
		t.Fatalf("expected 2.2.2.2 first (higher pressure), got %+v", top)
	}
}

func TestTopPressuredExcludesZero(t *testing.T) {
	s := New(testConfig())
	s.Record("3.3.3.3", 0, Webdriver)
	s.Record("3.3.3.3", 0, CleanPass) // halves to 5, still > 0 — should appear
	top := s.TopPressured(10)
	found := false
	for _, e := range top {
		if e.Key == "3.3.3.3" {
			found = true
		}
	}
	if !found {
		t.Fatal("a key with positive pressure should appear in TopPressured")
	}
}

func TestTopPressuredRespectsLimit(t *testing.T) {
	s := New(testConfig())
	for i := 0; i < 5; i++ {
		s.Record(string(rune('a'+i))+".ip", 0, Webdriver)
	}
	top := s.TopPressured(2)
	if len(top) != 2 {
		t.Fatalf("TopPressured(2) returned %d entries, want 2", len(top))
	}
}

func TestTopPressuredIncludesLastClean(t *testing.T) {
	s := New(testConfig())
	s.Record("4.4.4.4", 0, Webdriver)
	s.Record("4.4.4.4", 0, CleanPass)
	top := s.TopPressured(10)
	var entry *PressureEntry
	for i := range top {
		if top[i].Key == "4.4.4.4" {
			entry = &top[i]
		}
	}
	if entry == nil {
		t.Fatal("4.4.4.4 not found in TopPressured")
	}
	if entry.LastClean == nil {
		t.Fatal("LastClean should be set after a CleanPass event")
	}
}

func TestTopPressuredIncludesASNEntries(t *testing.T) {
	s := New(testConfig())
	s.Record("5.5.5.5", 6461, Webdriver)
	top := s.TopPressured(10)
	found := false
	for _, e := range top {
		if e.Kind == "asn" && e.Key == "AS6461" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an AS6461 entry, got %+v", top)
	}
}
