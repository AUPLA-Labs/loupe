package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/admin"
	"github.com/AUPLA-Labs/loupe/internal/badip"
	"github.com/AUPLA-Labs/loupe/internal/proof"
	"github.com/AUPLA-Labs/loupe/internal/tier"
)

func testBadIPFeed(t *testing.T, csv string, challengeAt, blockAt int) *badip.Feed {
	t.Helper()
	path := filepath.Join(t.TempDir(), "badips.csv")
	if err := os.WriteFile(path, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}
	return badip.New(badip.Options{CacheFile: path, ChallengeAt: challengeAt, BlockAt: blockAt})
}

// A listed address that answers the silent check cleanly is still sent to
// Prism: the feed's floor holds on the answer side, not only at dispatch.
func TestPulseResult_ListedAddressGoesToPrism(t *testing.T) {
	h := testPulseResultHandler(t)
	h.prismPath = "/loupe/prism"
	h.badIPs = testBadIPFeed(t, "ip,lists\n5.6.7.8,2\n", 1, 5)

	sp := issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, pulseSignalFields)
	if w := postPulseResult(t, h, "1.2.3.4", sp.ID, sealAnswered(t, sp, cleanPulseSignals)); !strings.Contains(w.Body.String(), `"action":"pass"`) {
		t.Fatalf("unlisted address: %q, want pass", w.Body.String())
	}
	sp = issueAnswerable(t, h, "5.6.7.8", proof.KindPulse, pulseSignalFields)
	w := postPulseResult(t, h, "5.6.7.8", sp.ID, sealAnswered(t, sp, cleanPulseSignals))
	if !strings.Contains(w.Body.String(), "/loupe/prism?return=") {
		t.Errorf("listed address: %q, want the prism puzzle", w.Body.String())
	}
}

func TestBadIPHelpers(t *testing.T) {
	h := &Handler{badIPs: testBadIPFeed(t, "ip,lists\n5.6.7.8,2\n9.9.9.9,7\n", 1, 5)}
	req := func(ip string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = ip + ":1234"
		return r
	}
	if h.badIPBlocked(req("5.6.7.8")) || h.prismRequired(req("5.6.7.8"), "5.6.7.8") != "bad_ip:2" {
		t.Error("2 lists: want Prism, not block")
	}
	if !h.badIPBlocked(req("9.9.9.9")) || h.prismRequired(req("9.9.9.9"), "9.9.9.9") != "" {
		t.Error("7 lists: want block")
	}
	if h.badIPBlocked(req("1.1.1.1")) || h.prismRequired(req("1.1.1.1"), "1.1.1.1") != "" {
		t.Error("unlisted: want nothing")
	}
	// Events carry the list count.
	if e := h.newEvent(req("9.9.9.9"), "9.9.9.9", 0, "", "BLOCK", "bad_ip_blocked", 0); e.BadIP != 7 {
		t.Errorf("event BadIP = %d, want 7", e.BadIP)
	}
	// Disabled feed: a nil pointer, never a panic.
	off := &Handler{}
	if off.badIPBlocked(req("9.9.9.9")) || off.prismRequired(req("9.9.9.9"), "9.9.9.9") != "" {
		t.Error("disabled feed acted")
	}
}

// The general case: a client dispatch escalated to Prism (request score,
// reputation) gets no easier clearance from the silent check either.
func TestPulseResult_PrismEscalationHolds(t *testing.T) {
	h := testPulseResultHandler(t)
	h.prismPath = "/loupe/prism"
	h.escalations.Require("1.2.3.4", tier.Prism, time.Minute)

	sp := issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, pulseSignalFields)
	w := postPulseResult(t, h, "1.2.3.4", sp.ID, sealAnswered(t, sp, cleanPulseSignals))
	if !strings.Contains(w.Body.String(), "/loupe/prism?return=") {
		t.Errorf("escalated client's clean pulse answer: %q, want the prism puzzle", w.Body.String())
	}
	if h.escalations.Level("1.2.3.4") != tier.Prism {
		t.Error("the escalation must survive until Prism is solved")
	}
}

// ... nor from the click challenge, whose pass would also have cleared the
// escalation, and without costing reputation (the address may be shared).
func TestServeVerify_PrismEscalationHolds(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(h *Handler)
		why   string
	}{
		{"escalated", func(h *Handler) { h.escalations.Require(verifyTestIP, tier.Prism, time.Minute) }, "escalation:prism"},
		{"listed", func(h *Handler) { h.badIPs = testBadIPFeed(t, "ip,lists\n"+verifyTestIP+",3\n", 1, 5) }, "bad_ip:3"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := testVerifyHandler(t)
			c.setup(h)
			var got []admin.Event
			h.store, _ = admin.NewStore(10, "")
			sp := issueAnswerableOpts(t, h, verifyTestIP, proof.KindChallenge, challengeSignalFields, true)
			v := decodeVerdict(t, postVerifyRaw(h, sp.ID, sealAnswered(t, sp, cleanSignals), "application/json"))
			if v["action"] != "redirect" || !strings.HasPrefix(v["url"], "/loupe/prism?return=") {
				t.Fatalf("verdict %v, want a redirect to the prism puzzle", v)
			}
			if p := h.reputation.IPPressure(verifyTestIP); p != 0 {
				t.Errorf("pressure %v, want none", p)
			}
			got = h.store.Query(admin.Query{}).Events
			if len(got) != 1 || got[0].Reason != "prism_required" || len(got[0].Reasons) != 1 || got[0].Reasons[0] != c.why {
				t.Errorf("events %+v, want one prism_required with %s", got, c.why)
			}
		})
	}
}
