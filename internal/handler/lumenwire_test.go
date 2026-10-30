package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/lumen"
	"github.com/AUPLA-Labs/loupe/internal/offender"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
	"github.com/AUPLA-Labs/loupe/internal/tier"
)

func testLumenHandler(t *testing.T, enforce bool) *Handler {
	t.Helper()
	cfg, err := config.LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Lumen.Enforce = enforce
	return &Handler{
		cfg:         cfg,
		offenders:   offender.New(5, time.Minute),
		escalations: offender.NewEscalations(),
		reputation:  testReputationStore(t),
	}
}

func lumenRequest(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/loupe/lumen", nil)
	r.RemoteAddr = ip + ":1234"
	return r
}

func TestLumenParams_EnforcedScalesWithSavedRequestScore(t *testing.T) {
	h := testLumenHandler(t, true)
	if p := h.lumenParams(lumenRequest("1.2.3.4"), "1.2.3.4", false); p.Level != lumen.Glow {
		t.Errorf("clean client: level %v, want glow", p.Level)
	}
	// Dispatch saw a navigation scoring 9 (malformed UA + missing Sec-Fetch).
	h.escalations.RequireLumen("5.6.7.8", 9, time.Minute)
	p := h.lumenParams(lumenRequest("5.6.7.8"), "5.6.7.8", false)
	if p.Level != lumen.Blinding || p.Work != 64*h.cfg.Lumen.Work {
		t.Errorf("suspicious client: %+v, want blinding at 64× work", p)
	}
	if p.MemoryBytes() != int64(h.cfg.Lumen.MaxMemoryMB)<<20 {
		t.Errorf("memory %d MB, want the %d MB ceiling", p.MemoryBytes()>>20, h.cfg.Lumen.MaxMemoryMB)
	}
}

func TestLumenParams_PulseNeverPastStandard(t *testing.T) {
	h := testLumenHandler(t, true)
	h.escalations.RequireLumen("5.6.7.8", 9, time.Minute)
	p := h.lumenParams(lumenRequest("5.6.7.8"), "5.6.7.8", true)
	if p.Level != lumen.Standard || p.Scored != lumen.Blinding || p.Work != h.cfg.Lumen.PulseWork {
		t.Errorf("pulse: %+v, want served at Standard with pulse work, scored Blinding", p)
	}
}

func TestLumenParams_ShadowServesLegacyDifficulty(t *testing.T) {
	h := testLumenHandler(t, false)
	h.escalations.RequireLumen("5.6.7.8", 9, time.Minute)
	p := h.lumenParams(lumenRequest("5.6.7.8"), "5.6.7.8", false)
	if p.Level != lumen.Standard || p.Scored != lumen.Blinding || p.Work != h.cfg.Lumen.Work {
		t.Errorf("shadow: %+v, want Standard at base work, scored Blinding", p)
	}

	// Shadow mode keeps the old pressure doubling, so it never lowers what
	// a pressured client paid before Lumen.
	h.reputation.Record("9.9.9.9", 0, reputation.VerifyFailure) // +3
	h.reputation.Record("9.9.9.9", 0, reputation.VerifyFailure) // +3
	p = h.lumenParams(lumenRequest("9.9.9.9"), "9.9.9.9", false)
	if want := lumen.LegacyWork(h.cfg.Lumen.Work, h.reputation.IPPressure("9.9.9.9")); p.Work != want || want <= h.cfg.Lumen.Work {
		t.Errorf("pressured shadow work = %d, want legacy %d (> base)", p.Work, want)
	}
}

func TestLumenParams_InFlightIssuanceIsNotHeldAgainstClient(t *testing.T) {
	h := testLumenHandler(t, true)
	h.offenders.Issued("1.2.3.4") // dispatch of the challenge being fetched now
	if p := h.lumenParams(lumenRequest("1.2.3.4"), "1.2.3.4", false); p.Level != lumen.Glow {
		t.Errorf("one in-flight challenge: level %v, want glow", p.Level)
	}
	for i := 0; i < 3; i++ {
		h.offenders.Issued("1.2.3.4") // ...and three it never answered
	}
	if p := h.lumenParams(lumenRequest("1.2.3.4"), "1.2.3.4", false); p.Level != lumen.Bright {
		t.Errorf("three unanswered: level %v, want bright", p.Level)
	}
}

func TestLumenParams_EscalationRaisesLevel(t *testing.T) {
	h := testLumenHandler(t, true)
	h.escalations.Require("1.2.3.4", tier.Prism, time.Minute)
	if p := h.lumenParams(lumenRequest("1.2.3.4"), "1.2.3.4", false); p.Level != lumen.Standard {
		t.Errorf("prism-escalated: level %v, want standard", p.Level)
	}
	h.escalations.RequireLumen("1.2.3.4", 2, time.Minute) // plus a header oddity
	if p := h.lumenParams(lumenRequest("1.2.3.4"), "1.2.3.4", false); p.Level != lumen.Bright {
		t.Errorf("prism-escalated with request score 2: level %v, want bright", p.Level)
	}
}
