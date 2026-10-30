package admin

import (
	"testing"
	"time"
)

func TestStatsBehaviour(t *testing.T) {
	s := newTestStore(t, 100)
	now := time.Now()
	add := func(ip, reason string, score int, sigs ...string) {
		s.Add(Event{Time: now.Add(-time.Minute), IP: ip, Action: "ALLOW", Reason: reason, Score: score, Reasons: sigs})
	}
	add("1.1.1.1", "clearance", 3, "path_enumeration")
	add("1.1.1.1", "clearance", 4, "path_enumeration", "no_referrer_chain")
	add("2.2.2.2", "clearance", 2, "nav_too_regular")
	add("3.3.3.3", "clearance", 0)
	s.Add(Event{Time: now.Add(-time.Minute), IP: "1.1.1.1", Action: "CHALLENGE", Reason: "clearance_behaviour"})

	b := s.StatsFor(LookupWindow("24h"), now).Behaviour
	if b.Flagged != 3 || b.Dropped != 1 || b.BySignal["path_enumeration"] != 2 || b.BySignal["nav_too_regular"] != 1 {
		t.Fatalf("behaviour stats %+v", b)
	}
	if len(b.TopIPs) != 2 || b.TopIPs[0].IP != "1.1.1.1" || b.TopIPs[0].Count != 2 {
		t.Fatalf("top IPs %+v, want 1.1.1.1 first with 2", b.TopIPs)
	}
}
