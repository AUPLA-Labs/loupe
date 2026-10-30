package admin

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
)

func TestStatsBadIP(t *testing.T) {
	s, _ := NewStore(100, "")
	now := time.Now()
	add := func(ip, action, reason string, lists int) {
		s.Add(Event{Time: now.Add(-time.Minute), IP: ip, Action: action, Reason: reason, BadIP: lists})
	}
	add("1.1.1.1", "CHALLENGE", "bad_ip", 2)
	add("1.1.1.1", "PASS", "", 2)
	add("1.1.1.1", "ALLOW", "clearance", 2)
	add("2.2.2.2", "BLOCK", "bad_ip_blocked", 7)
	add("3.3.3.3", "ALLOW", "clearance", 0)

	b := s.StatsFor(LookupWindow("1h"), now).BadIP
	if b.Total != 4 || b.UniqueIPs != 2 {
		t.Fatalf("total %d unique %d, want 4 and 2", b.Total, b.UniqueIPs)
	}
	if b.ByAction["CHALLENGE"] != 1 || b.ByAction["BLOCK"] != 1 || b.ByReason["bad_ip_blocked"] != 1 {
		t.Errorf("by action %v, by reason %v", b.ByAction, b.ByReason)
	}
	if len(b.ByLists) != 8 || b.ByLists[2] != 1 || b.ByLists[7] != 1 {
		t.Errorf("by lists %v", b.ByLists)
	}
	if len(b.TopIPs) != 2 || b.TopIPs[0].IP != "1.1.1.1" || b.TopIPs[0].Lists != 2 {
		t.Errorf("top %+v", b.TopIPs)
	}

	res := s.Query(ParseQuery(url.Values{"badip": {"1"}}))
	if len(res.Events) != 4 {
		t.Errorf("badip filter matched %d events, want 4", len(res.Events))
	}
}

func TestCheckOrderingBadIPs(t *testing.T) {
	c := &config.Config{}
	c.Hardening.RequestScore = config.RequestScoreConfig{Tier2: 2, Tier3: 4, Tier4: 9}
	c.Reputation.Floors = config.ReputationFloors{Tier2: 4, Tier3: 12, Tier4: 40}
	c.Lumen = config.LumenConfig{Work: 2, PulseWork: 1, MemoryMB: 2, PulseMemoryMB: 1, MaxMemoryMB: 4}
	c.BadIPs = config.BadIPsConfig{ChallengeAt: 3, BlockAt: 2}
	if checkOrdering(c) == nil {
		t.Error("block_at below challenge_at accepted")
	}
	c.BadIPs.BlockAt = 0
	if err := checkOrdering(c); err != nil {
		t.Errorf("block_at 0 (never) rejected: %v", err)
	}
}

func TestCheckOrderingClearanceBudget(t *testing.T) {
	c := &config.Config{}
	c.Hardening.RequestScore = config.RequestScoreConfig{Tier2: 2, Tier3: 4, Tier4: 9}
	c.Reputation.Floors = config.ReputationFloors{Tier2: 4, Tier3: 12, Tier4: 40}
	c.Lumen = config.LumenConfig{Work: 2, PulseWork: 1, MemoryMB: 2, PulseMemoryMB: 1, MaxMemoryMB: 4}
	c.Abuse.ClearanceBudget = config.ClearanceBudgetConfig{DocBurst: 300, AllBurst: 200}
	if err := checkOrdering(c); err == nil || !strings.Contains(err.Error(), "burst") {
		t.Errorf("all_burst below doc_burst: err = %v, want a burst ordering error", err)
	}
	c.Abuse.ClearanceBudget.AllBurst = 300
	if err := checkOrdering(c); err != nil {
		t.Errorf("all_burst equal to doc_burst rejected: %v", err)
	}
}

func TestClearanceBurstMinimums(t *testing.T) {
	tests := []struct {
		key  string
		val  string
		fail bool
	}{
		{"abuse.clearance_budget.doc_burst", "5", true},
		{"abuse.clearance_budget.doc_burst", "10", false},
		{"abuse.clearance_budget.all_burst", "50", true},
		{"abuse.clearance_budget.all_burst", "100", false},
	}
	for _, tt := range tests {
		_, err := settingEdits(map[string]json.RawMessage{tt.key: json.RawMessage(tt.val)})
		if (err != nil) != tt.fail {
			t.Errorf("%s = %s: err = %v, want failure %v", tt.key, tt.val, err, tt.fail)
		}
	}
}

func TestSettingsCreateBadIPsSection(t *testing.T) {
	edits, err := settingEdits(map[string]json.RawMessage{"bad_ips.block_at": json.RawMessage("6"), "bad_ips.enabled": json.RawMessage("true")})
	if err != nil {
		t.Fatal(err)
	}
	out, err := config.ApplyEdits([]byte("listen: \":8080\"\n"), edits)
	if err != nil {
		t.Fatalf("settings must be able to add a missing bad_ips section: %v", err)
	}
	cfg, err := config.LoadBytes(out)
	if err != nil || !cfg.BadIPs.Enabled || cfg.BadIPs.BlockAt != 6 {
		t.Errorf("got %+v, %v from:\n%s", cfg.BadIPs, err, out)
	}
}
