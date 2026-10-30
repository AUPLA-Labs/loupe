package handler

import (
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/proof"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
	"github.com/AUPLA-Labs/loupe/internal/tier"
)

func testHashes() map[string]string {
	return map[string]string{
		"canvas": "c1", "audio": "a1", "webgl": "w1", "webgl_render": "r1", "fonts": "f1",
		"screen": "s1", "engine": "e1", "features": "x1", "nav": "n1", "intl": "i1",
	}
}

func TestClusterKeys(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	chrome := parseUAClaims(fpChrome126Linux)
	d1, b1 := clusterKeys("secret", now, testHashes(), chrome, false)
	if len(d1) != 16 || len(b1) != 16 {
		t.Fatalf("keys = %q %q, want 16 hex each", d1, b1)
	}
	if d2, b2 := clusterKeys("secret", now.Add(time.Hour), testHashes(), chrome, false); d2 != d1 || b2 != b1 {
		t.Error("keys must be stable within an epoch")
	}
	if d3, _ := clusterKeys("secret", now.Add(clusterKeyEpoch), testHashes(), chrome, false); d3 == d1 {
		t.Error("keys must rotate with the epoch")
	}
	if d4, _ := clusterKeys("other", now, testHashes(), chrome, false); d4 == d1 {
		t.Error("keys must depend on the server secret")
	}

	// Surfaces observed to vary between visits never enter the device key.
	h := testHashes()
	h["nav"], h["intl"], h["media"], h["voices"] = "n2", "i2", "m2", "v2"
	if d, _ := clusterKeys("secret", now, h, chrome, false); d != d1 {
		t.Error("nav/intl/media/voices must not affect the device key")
	}
	h = testHashes()
	h["canvas"] = "c2"
	if d, _ := clusterKeys("secret", now, h, chrome, false); d == d1 {
		t.Error("canvas must affect a Chrome device key")
	}

	// A missing input means no device key at all, not a partial one.
	h = testHashes()
	delete(h, "audio")
	if d, b := clusterKeys("secret", now, h, chrome, false); d != "" || b != b1 {
		t.Errorf("missing audio: device=%q build=%q, want no device key and the same build key", d, b)
	}

	// Brave re-farbles canvas/audio/screen per page load: its key ignores them.
	hb := testHashes()
	db, _ := clusterKeys("secret", now, hb, chrome, true)
	hb["canvas"], hb["audio"], hb["screen"], hb["webgl"] = "c9", "a9", "s9", "w9"
	if d, _ := clusterKeys("secret", now, hb, chrome, true); d != db || d == "" {
		t.Error("Brave device key must ignore farbled surfaces")
	}

	// Safari may add noise to canvas and audio.
	safari := parseUAClaims(fpSafari18Mac)
	hs := testHashes()
	ds, _ := clusterKeys("secret", now, hs, safari, false)
	hs["canvas"], hs["audio"] = "c9", "a9"
	if d, _ := clusterKeys("secret", now, hs, safari, false); d != ds || d == "" {
		t.Error("Safari device key must ignore canvas and audio")
	}

	if d, b := clusterKeys("secret", now, nil, chrome, false); d != "" || b != "" {
		t.Error("no hashes must yield no keys")
	}
}

func newTestTracker() *clusterTracker {
	return &clusterTracker{
		deviceIPs:  make(map[string]map[string]time.Time),
		deviceASNs: make(map[string]map[uint]time.Time),
		ipDevices:  make(map[string]map[string]deviceSeen),
	}
}

func TestClusterTracker_Rotation(t *testing.T) {
	tr := newTestTracker()
	now := time.Now()
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
	for _, ip := range ips {
		if rot, _ := tr.observe("dev", "b", ip, 100, true, now); rot {
			t.Fatalf("rotation fired below threshold at %s", ip)
		}
	}
	if rot, _ := tr.observe("dev", "b", "1.1.1.1", 100, true, now); rot {
		t.Error("a repeat IP must not trigger rotation")
	}
	if rot, _ := tr.observe("dev", "b", "5.5.5.5", 100, true, now); !rot {
		t.Error("the 5th distinct IP must trigger rotation")
	}
	// Outside the window, old observations no longer count.
	if rot, _ := tr.observe("dev2", "b", "9.9.9.1", 1, true, now.Add(-2*time.Hour)); rot {
		t.Fatal("unexpected")
	}

	tr = newTestTracker()
	tr.observe("dev", "b", "1.1.1.1", 1, true, now)
	tr.observe("dev", "b", "1.1.1.1", 2, true, now)
	if rot, _ := tr.observe("dev", "b", "1.1.1.1", 3, true, now); !rot {
		t.Error("the 3rd distinct ASN must trigger rotation")
	}
}

func TestClusterTracker_Churn(t *testing.T) {
	now := time.Now()
	tr := newTestTracker()
	for i, d := range []string{"d1", "d2", "d3"} {
		if _, churn := tr.observe(d, "build", "1.1.1.1", 1, true, now); churn {
			t.Fatalf("churn fired at device %d", i+1)
		}
	}
	if _, churn := tr.observe("d4", "build", "1.1.1.1", 1, true, now); !churn {
		t.Error("the 4th device of one build from one IP must trigger churn")
	}

	// A NAT full of different browsers is not churn.
	tr = newTestTracker()
	for i, d := range []string{"d1", "d2", "d3", "d4", "d5"} {
		if _, churn := tr.observe(d, "build"+d, "1.1.1.1", 1, true, now); churn {
			t.Fatalf("different builds triggered churn at device %d", i+1)
		}
	}

	// Ineligible clients (Brave) never trigger churn.
	tr = newTestTracker()
	for _, d := range []string{"d1", "d2", "d3", "d4", "d5"} {
		if _, churn := tr.observe(d, "build", "1.1.1.1", 1, false, now); churn {
			t.Fatal("ineligible client triggered churn")
		}
	}
}

func TestClientFloor_BuildCapped(t *testing.T) {
	s := reputation.New(reputation.Config{})
	for i := 0; i < 50; i++ {
		s.RecordBuild("b", reputation.BuildConclusive)
	}
	if f := s.ClientFloor("", "b"); f != tier.LumenAuto {
		t.Errorf("build floor = %v, want capped at lumen_auto", f)
	}
	for i := 0; i < 5; i++ {
		s.RecordDevice("d", reputation.Webdriver)
	}
	if f := s.ClientFloor("d", "b"); f != tier.Prism {
		t.Errorf("device floor at pressure 50 = %v, want prism", f)
	}
	s.RecordDevice("d", reputation.CleanPass)
	if p := s.DevicePressure("d"); p > 25.01 {
		t.Errorf("clean pass must halve device pressure, got %v", p)
	}
}

// End to end: a device key carrying pressure turns an otherwise clean pulse
// answer into a challenge, and the answer's keys are logged.
func TestPulseResult_ClusterFloorEscalates(t *testing.T) {
	h := testPulseResultHandler(t)
	h.clusters = newTestTracker()
	h.prismPath = "/loupe/prism"

	// First answer: clean pass, learn its device key.
	sp := issueAnswerable(t, h, "1.2.3.4", proof.KindPulse, pulseSignalFields)
	sealed := sealAnswered(t, sp, cleanPulseSignals)
	sig, _ := sp.Unseal(sealed)
	hashes := fingerprintHashes(sig["fp"])
	device, _ := clusterKeys(h.cfg.HMACSecret, time.Now(), hashes, parseUAClaims(""), false)
	if device == "" {
		t.Fatal("fixture fingerprint must produce a device key")
	}
	if w := postPulseResult(t, h, "1.2.3.4", sp.ID, sealed); !strings.Contains(w.Body.String(), `"action":"pass"`) {
		t.Fatalf("clean first answer: %q", w.Body.String())
	}

	// The device then racks up conclusive automation elsewhere.
	for i := 0; i < 5; i++ {
		h.reputation.RecordDevice(device, reputation.Webdriver)
	}
	sp = issueAnswerable(t, h, "5.6.7.8", proof.KindPulse, pulseSignalFields)
	w := postPulseResult(t, h, "5.6.7.8", sp.ID, sealAnswered(t, sp, cleanPulseSignals))
	if !strings.Contains(w.Body.String(), "/loupe/prism?return=") {
		t.Errorf("pressured device from a fresh IP: %q, want the prism puzzle", w.Body.String())
	}
}
