package offender

import (
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

func TestUnknownKeyHasNoEscalation(t *testing.T) {
	e := NewEscalations()
	if got := e.Level("1.2.3.4"); got != tier.Pass {
		t.Fatalf("unknown key should have no escalation, got %v", got)
	}
}

func TestRequireRecordsLevel(t *testing.T) {
	e := NewEscalations()
	e.Require("1.2.3.4", tier.SingleClick, time.Minute)
	if got := e.Level("1.2.3.4"); got != tier.SingleClick {
		t.Fatalf("Level = %v, want %v", got, tier.SingleClick)
	}
}

func TestRequireOnlyRaisesNeverLowers(t *testing.T) {
	// This is the security property the whole type exists for: once the server
	// has decided a client needs a harder challenge, nothing may walk that back.
	e := NewEscalations()
	e.Require("1.2.3.4", tier.Prism, time.Minute)
	e.Require("1.2.3.4", tier.LumenAuto, time.Minute)
	if got := e.Level("1.2.3.4"); got != tier.Prism {
		t.Fatalf("a lower Require must not reduce the level: got %v, want %v", got, tier.Prism)
	}
}

func TestRequireRefreshesExpiryOnRepeat(t *testing.T) {
	e := NewEscalations()
	e.Require("1.2.3.4", tier.SingleClick, 200*time.Millisecond)
	time.Sleep(120 * time.Millisecond)
	e.Require("1.2.3.4", tier.SingleClick, 200*time.Millisecond)
	time.Sleep(120 * time.Millisecond)
	if got := e.Level("1.2.3.4"); got != tier.SingleClick {
		t.Fatalf("expiry should have been refreshed by the second Require, got %v", got)
	}
}

func TestEscalationExpires(t *testing.T) {
	e := NewEscalations()
	e.Require("1.2.3.4", tier.Prism, 10*time.Millisecond)
	time.Sleep(25 * time.Millisecond)
	if got := e.Level("1.2.3.4"); got != tier.Pass {
		t.Fatalf("escalation should have expired, got %v", got)
	}
}

func TestClearRemovesEscalation(t *testing.T) {
	e := NewEscalations()
	e.Require("1.2.3.4", tier.Prism, time.Minute)
	e.Clear("1.2.3.4")
	if got := e.Level("1.2.3.4"); got != tier.Pass {
		t.Fatalf("Clear should have removed the escalation, got %v", got)
	}
}

func TestEscalationsArePerKey(t *testing.T) {
	e := NewEscalations()
	e.Require("1.2.3.4", tier.Prism, time.Minute)
	if got := e.Level("5.6.7.8"); got != tier.Pass {
		t.Fatalf("escalation leaked to a different key, got %v", got)
	}
}

func TestLowerRequireRefreshesExpiry(t *testing.T) {
	// A lower-level Require should still refresh the expiry as documented.
	e := NewEscalations()
	e.Require("1.2.3.4", tier.Prism, 200*time.Millisecond)
	time.Sleep(120 * time.Millisecond)
	e.Require("1.2.3.4", tier.SingleClick, 200*time.Millisecond)
	time.Sleep(120 * time.Millisecond)
	if got := e.Level("1.2.3.4"); got != tier.Prism {
		t.Fatalf("level should remain at Prism (not lowered), got %v", got)
	}
}

func TestExpiredFollowedByLowerRequire(t *testing.T) {
	// After an escalation expires, a lower Require should settle at the lower level.
	e := NewEscalations()
	e.Require("1.2.3.4", tier.Prism, 10*time.Millisecond)
	time.Sleep(25 * time.Millisecond)
	if got := e.Level("1.2.3.4"); got != tier.Pass {
		t.Fatalf("escalation should have expired, got %v", got)
	}
	e.Require("1.2.3.4", tier.SingleClick, time.Minute)
	if got := e.Level("1.2.3.4"); got != tier.SingleClick {
		t.Fatalf("after expiry, lower Require should set new level, got %v", got)
	}
}

func TestShorterTTLDoesNotTruncateLonger(t *testing.T) {
	// A Require with a shorter TTL must not truncate a live higher escalation.
	// The level stays the same (Require only raises), and the expiry stays longer.
	e := NewEscalations()
	e.Require("1.2.3.4", tier.Prism, 500*time.Millisecond)
	e.Require("1.2.3.4", tier.SingleClick, 10*time.Millisecond)
	time.Sleep(25 * time.Millisecond)
	// The level should still be Prism (not lowered), and it should not have expired.
	if got := e.Level("1.2.3.4"); got != tier.Prism {
		t.Fatalf("short TTL Require should not lower the level, got %v", got)
	}
}

func TestRequireLumenOnlyRaisesAndSharesEntry(t *testing.T) {
	e := NewEscalations()
	e.RequireLumen("1.2.3.4", 5, time.Minute)
	e.RequireLumen("1.2.3.4", 2, time.Minute)
	if got := e.Lumen("1.2.3.4"); got != 5 {
		t.Fatalf("lumen = %d, want 5 (never lowered)", got)
	}
	e.Require("1.2.3.4", tier.SingleClick, time.Minute)
	if got := e.Lumen("1.2.3.4"); got != 5 {
		t.Errorf("Require dropped the lumen score: %d", got)
	}
	if got := e.Level("1.2.3.4"); got != tier.SingleClick {
		t.Errorf("RequireLumen disturbed the tier: %v", got)
	}
	e.Clear("1.2.3.4")
	if got := e.Lumen("1.2.3.4"); got != 0 {
		t.Errorf("lumen after Clear = %d", got)
	}
	if got := e.Lumen("5.6.7.8"); got != 0 {
		t.Errorf("unknown key lumen = %d", got)
	}
}

func TestRequireLumenDoesNotExtendTierEscalation(t *testing.T) {
	e := NewEscalations()
	e.Require("1.2.3.4", tier.SingleClick, 20*time.Millisecond)
	e.RequireLumen("1.2.3.4", 3, time.Hour)
	time.Sleep(30 * time.Millisecond)
	if got := e.Level("1.2.3.4"); got != tier.Pass {
		t.Errorf("tier escalation outlived its ttl: %v", got)
	}
	if got := e.Lumen("1.2.3.4"); got != 3 {
		t.Errorf("lumen score = %d, want 3", got)
	}
}

func TestDemandLumenOnlyRaisesAndKeepsRequestScore(t *testing.T) {
	e := NewEscalations()
	e.RequireLumen("1.2.3.4", 2, time.Minute)
	e.DemandLumen("1.2.3.4", 3, time.Minute)
	e.DemandLumen("1.2.3.4", 2, time.Minute)
	if got := e.LumenDemand("1.2.3.4"); got != 3 {
		t.Fatalf("demand = %d, want 3 (never lowered)", got)
	}
	if got := e.Lumen("1.2.3.4"); got != 2 {
		t.Errorf("DemandLumen disturbed the request score: %d", got)
	}
	e.RequireLumen("1.2.3.4", 4, time.Minute)
	if got := e.LumenDemand("1.2.3.4"); got != 3 {
		t.Errorf("RequireLumen disturbed the demand: %d", got)
	}
	e.Clear("1.2.3.4")
	if got := e.LumenDemand("1.2.3.4"); got != 0 {
		t.Errorf("demand after Clear = %d", got)
	}
}
