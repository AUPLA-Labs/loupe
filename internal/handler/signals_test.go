package handler

import "testing"

func TestPuzzleScoreSignals_CleanSignals(t *testing.T) {
	sig := map[string]interface{}{
		"screenW":      1920.0,
		"screenH":      1080.0,
		"languages":    "en-US,en",
		"dragDuration": 800.0,
		"preDragTime":  1500.0,
		"attempts":     1.0,
		"dragPath": []interface{}{
			[]interface{}{100.0, 100.0, 0.0},
			[]interface{}{120.0, 115.0, 100.0},
			[]interface{}{145.0, 130.0, 200.0},
			[]interface{}{200.0, 160.0, 350.0},
		},
	}
	score, reasons := reflexPrismScore(sig)
	if score != 0 {
		t.Errorf("clean signals: expected score 0, got %d reasons=%v", score, reasons)
	}
}

func TestPuzzleScoreSignals_TooFastDrag(t *testing.T) {
	sig := map[string]interface{}{
		"screenW": 1920.0, "screenH": 1080.0, "languages": "en-US",
		"dragDuration": 80.0, "preDragTime": 1000.0, "attempts": 1.0,
	}
	score, reasons := reflexPrismScore(sig)
	if score < 3 {
		t.Errorf("too_fast_drag: expected score>=3, got %d reasons=%v", score, reasons)
	}
	if !containsReason(reasons, "too_fast_drag") {
		t.Errorf("missing reason too_fast_drag, got %v", reasons)
	}
}

func TestPuzzleScoreSignals_InstantDrag(t *testing.T) {
	sig := map[string]interface{}{
		"screenW": 1920.0, "screenH": 1080.0, "languages": "en-US",
		"dragDuration": 500.0, "preDragTime": 200.0, "attempts": 1.0,
	}
	score, reasons := reflexPrismScore(sig)
	if score < 2 {
		t.Errorf("instant_drag: expected score>=2, got %d reasons=%v", score, reasons)
	}
	if !containsReason(reasons, "instant_drag") {
		t.Errorf("missing reason instant_drag, got %v", reasons)
	}
}

func TestPuzzleScoreSignals_NoDragAttempt(t *testing.T) {
	sig := map[string]interface{}{
		"screenW": 1920.0, "screenH": 1080.0, "languages": "en-US",
		"dragDuration": 0.0, "preDragTime": 0.0, "attempts": 0.0,
	}
	score, reasons := reflexPrismScore(sig)
	if score < 2 {
		t.Errorf("no_drag_attempt: expected score>=2, got %d reasons=%v", score, reasons)
	}
	if !containsReason(reasons, "no_drag_attempt") {
		t.Errorf("missing reason no_drag_attempt, got %v", reasons)
	}
}

func TestPuzzleScoreSignals_TinyScreen(t *testing.T) {
	sig := map[string]interface{}{
		"screenW": 100.0, "screenH": 100.0, "languages": "en-US",
		"dragDuration": 500.0, "preDragTime": 1000.0, "attempts": 1.0,
	}
	score, reasons := reflexPrismScore(sig)
	if score < 3 {
		t.Errorf("tiny_screen: expected score>=3, got %d reasons=%v", score, reasons)
	}
	if !containsReason(reasons, "tiny_screen") {
		t.Errorf("missing reason tiny_screen, got %v", reasons)
	}
}

func TestIsLinearDrag_Horizontal(t *testing.T) {
	path := []interface{}{
		[]interface{}{0.0, 50.0, 0.0},
		[]interface{}{50.0, 50.0, 100.0},
		[]interface{}{100.0, 50.0, 200.0},
		[]interface{}{150.0, 50.0, 300.0},
		[]interface{}{200.0, 50.0, 400.0},
	}
	if !isLinearDrag(path) {
		t.Error("perfectly horizontal drag should be linear")
	}
}

func TestIsLinearDrag_Curved(t *testing.T) {
	path := []interface{}{
		[]interface{}{0.0, 0.0, 0.0},
		[]interface{}{50.0, 40.0, 100.0},
		[]interface{}{100.0, -30.0, 200.0},
		[]interface{}{150.0, 20.0, 300.0},
		[]interface{}{200.0, 0.0, 400.0},
	}
	if isLinearDrag(path) {
		t.Error("curved path should not be linear")
	}
}

func TestIsLinearDrag_TooFewPoints(t *testing.T) {
	path := []interface{}{
		[]interface{}{0.0, 0.0, 0.0},
		[]interface{}{100.0, 0.0, 100.0},
	}
	if isLinearDrag(path) {
		t.Error("2-point path should not be flagged as linear")
	}
}

func containsReason(reasons []string, target string) bool {
	for _, r := range reasons {
		if r == target {
			return true
		}
	}
	return false
}

func TestScoreSignals_LowMouseJitter(t *testing.T) {
	sig := map[string]interface{}{
		"mouseMoved":       true,
		"mouseJitter":      0.5,
		"velocityVariance": 999.0,
	}
	score, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if score < 3 {
		t.Errorf("low jitter: expected score>=3, got %d %v", score, reasons)
	}
	if !containsReason(reasons, "low_mouse_jitter") {
		t.Errorf("missing low_mouse_jitter in %v", reasons)
	}
	if containsReason(reasons, "low_mouse_jitter_singleclick") {
		t.Errorf("requiresSingleClick=false must not use the singleclick-weighted reason, got %v", reasons)
	}
}

// TestScoreSignals_LowMouseJitterOnRequiredSingleClickAloneReachesBlock pins a
// real observed bypass: a client that suppresses navigator.webdriver
// (e.g. Chromium launched with --disable-blink-features=AutomationControlled)
// and drives the mouse via humanized-but-still-too-smooth synthetic movement
// can reach a manual/single-click challenge with reputation pressure already
// forcing requiresSingleClick=true, then pass with only a "suspicious" score
// of 3 — below scoreBlock — because a genuine human being asked to perform
// one deliberate click and producing near-zero physical-tremor jitter while
// doing it is implausible enough, in that already-filtered population, to be
// treated as conclusive on its own rather than merely suggestive.
func TestScoreSignals_LowMouseJitterOnRequiredSingleClickAloneReachesBlock(t *testing.T) {
	sig := map[string]interface{}{
		// Otherwise-clean signals (mirrors TestReflexScore_LowJitterAndLinearDragDoNotDoubleCount)
		// so only the singleclick-weighted jitter check is in play, and the
		// resulting score can be pinned exactly rather than just bounded.
		"languages":           "en-US,en",
		"screenW":             1920.0,
		"screenH":             1080.0,
		"colorDepth":          24.0,
		"outerWidth":          1920.0,
		"outerHeight":         1040.0,
		"innerHeight":         900.0,
		"maxTouchPoints":      0.0,
		"availW":              1920.0,
		"availH":              1040.0,
		"hardwareConcurrency": 8.0,
		"rafVariance":         5.0,
		"firstInteractionMs":  800.0,
		"mouseMoved":          true,
		"mouseJitter":         0.5,
		"velocityVariance":    999.0,
		"movementDeltaSeen":   true,
		"manual":              true,
		"clickTrusted":        true,
	}
	score, reasons := reflexScore(sig, chromeDesktopUA, true, true)
	if score != scoreBlock {
		t.Errorf("low jitter alone on a required single-click: expected score==%d (scoreBlock), got %d %v", scoreBlock, score, reasons)
	}
	if !containsReason(reasons, "low_mouse_jitter_singleclick") {
		t.Errorf("missing low_mouse_jitter_singleclick in %v", reasons)
	}
	if containsReason(reasons, "low_mouse_jitter") {
		t.Errorf("requiresSingleClick=true must use the singleclick-weighted reason instead of the base one, got %v", reasons)
	}
}

func TestIsKnownBotUA_HeadlessChrome(t *testing.T) {
	// Playwright's default headless Chromium launch identifies itself with
	// this exact token — a real, observed bypass attempt reached only the
	// lowest challenge tier because nothing checked for it. No genuine
	// browser ever sends "Headless" in its own User-Agent.
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/147.0.7727.15 Safari/537.36"
	if !isKnownBotUA(ua, nil) {
		t.Errorf("expected HeadlessChrome UA to be caught by isKnownBotUA: %q", ua)
	}
}

func TestIsKnownBotUA_OrdinaryChromeIsNotFlagged(t *testing.T) {
	if isKnownBotUA(chromeDesktopUA, nil) {
		t.Errorf("ordinary Chrome UA must not be flagged: %q", chromeDesktopUA)
	}
}

func TestScoreSignals_UniformRAF(t *testing.T) {
	sig := map[string]interface{}{
		"rafVariance": 0.1,
	}
	score, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if score < 3 {
		t.Errorf("uniform rAF: expected score>=3, got %d %v", score, reasons)
	}
	if !containsReason(reasons, "uniform_raf") {
		t.Errorf("missing uniform_raf in %v", reasons)
	}
}

func TestScoreSignals_FastFirstInteraction(t *testing.T) {
	sig := map[string]interface{}{
		"firstInteractionMs": 50.0,
		"firstDeliberateMs":  50.0,
	}
	score, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if score < 2 {
		t.Errorf("fast interaction: expected score>=2, got %d %v", score, reasons)
	}
	if !containsReason(reasons, "fast_first_interaction") {
		t.Errorf("missing fast_first_interaction in %v", reasons)
	}
}

func TestScoreSignals_PasteInput(t *testing.T) {
	sig := map[string]interface{}{
		"keyCount": 5.0,
		"ikiMax":   10.0,
	}
	score, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if !containsReason(reasons, "paste_or_programmatic_input") {
		t.Errorf("missing paste signal in %v, score=%d", reasons, score)
	}
}

func TestScoreSignals_UniformScroll(t *testing.T) {
	sig := map[string]interface{}{
		"scrollCount":       5.0,
		"scrollIntervalVar": 100.0,
	}
	score, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if !containsReason(reasons, "uniform_scroll_intervals") {
		t.Errorf("missing uniform_scroll_intervals in %v, score=%d", reasons, score)
	}
}

func TestScoreSignals_ConsistencyChecks(t *testing.T) {
	tests := []struct {
		name     string
		sig      map[string]interface{}
		reason   string
		minScore int
	}{
		{
			"platform_tz_mismatch",
			map[string]interface{}{"platformTzMismatch": true},
			"platform_tz_mismatch", 1,
		},
		{
			"zero_hw_concurrency",
			map[string]interface{}{"hardwareConcurrency": 0.0, "maxTouchPoints": 0.0},
			"zero_hw_concurrency", 2,
		},
		{
			"color_depth_sub24",
			map[string]interface{}{"colorDepth": 16.0, "maxTouchPoints": 0.0},
			"color_depth_sub24", 1,
		},
		{
			"low_device_memory",
			map[string]interface{}{"deviceMemory": 0.25, "maxTouchPoints": 0.0},
			"low_device_memory", 1,
		},
		{
			"language_inconsistent",
			map[string]interface{}{"languageInconsistent": true},
			"language_inconsistent", 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, reasons := reflexScore(tt.sig, chromeDesktopUA, false, false)
			if score < tt.minScore {
				t.Errorf("expected score>=%d, got %d %v", tt.minScore, score, reasons)
			}
			if !containsReason(reasons, tt.reason) {
				t.Errorf("missing reason %q in %v", tt.reason, reasons)
			}
		})
	}
}

func TestScoreSignals_CleanBehavior(t *testing.T) {
	sig := map[string]interface{}{
		"mouseMoved":          true,
		"mouseJitter":         50.0,
		"velocityVariance":    2.0,
		"rafVariance":         5.0,
		"firstInteractionMs":  800.0,
		"languages":           "en-US,en",
		"screenW":             1920.0,
		"screenH":             1080.0,
		"colorDepth":          24.0,
		"outerWidth":          1920.0,
		"outerHeight":         1040.0,
		"innerHeight":         900.0,
		"maxTouchPoints":      0.0,
		"availW":              1920.0,
		"availH":              1040.0,
		"hardwareConcurrency": 8.0,
	}
	score, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if score != 0 {
		t.Errorf("clean signals: expected score 0, got %d %v", score, reasons)
	}
}

const probeChrome131UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36"
const probeIOSUA = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
const probeAndroidUA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"

// chromeDesktopUA is a generic desktop Chrome UA for reflexScore tests where
// the UA claim itself is not what's under test but reflexScore's
// claims.isChromium-gated checks (e.g. zero_movement_delta) need a Chromium
// claim to behave as in production.
const chromeDesktopUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36"

// firefoxDesktopUA is a non-Chromium UA, used to confirm Chromium-gated
// checks correctly stay off for a real non-Chromium browser.
const firefoxDesktopUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"

func cleanProbeChromeSignals() map[string]interface{} {
	return map[string]interface{}{
		"screenW": 1920.0, "screenH": 1080.0, "innerWidth": 1900.0, "innerHeight": 950.0,
		"colorDepth": 24.0, "outerWidth": 1920.0, "languages": "en-US,en",
		"maxTouchPoints": 0.0, "hardwareConcurrency": 8.0, "deviceMemory": 8.0,
		"hasUaData": true, "uaDataBrandVersion": 131.0, "webdriverPropPresent": true,
		"hasWindowChrome": true, "devicePixelRatio": 1.0,
	}
}

func TestReflexProbeScore_CleanChromeDesktopIsZero(t *testing.T) {
	score, reasons := reflexProbeScore(cleanProbeChromeSignals(), probeChrome131UA)
	if score != 0 {
		t.Errorf("clean Chrome 131 desktop: score = %d, reasons = %v, want 0", score, reasons)
	}
}

func TestReflexProbeScore_UADataMismatch(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["uaDataBrandVersion"] = 99.0 // UA string claims 131
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if !containsReason(reasons, "ua_data_mismatch") {
		t.Errorf("expected ua_data_mismatch, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_WebdriverPropDeleted(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["webdriverPropPresent"] = false
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if !containsReason(reasons, "webdriver_prop_deleted") {
		t.Errorf("expected webdriver_prop_deleted, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_NoUAData(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["hasUaData"] = false
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if !containsReason(reasons, "no_ua_data") {
		t.Errorf("expected no_ua_data, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_ViewportExceedsScreen(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["innerWidth"] = 3000.0
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if !containsReason(reasons, "viewport_exceeds_screen") {
		t.Errorf("expected viewport_exceeds_screen, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_IOSDPR1(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["maxTouchPoints"] = 5.0
	sig["devicePixelRatio"] = 1.0
	score, reasons := reflexProbeScore(sig, probeIOSUA)
	if !containsReason(reasons, "ios_dpr_1") {
		t.Errorf("expected ios_dpr_1, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_RealIOSDPRIsNeverOne(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["maxTouchPoints"] = 5.0
	sig["devicePixelRatio"] = 3.0
	score, reasons := reflexProbeScore(sig, probeIOSUA)
	if containsReason(reasons, "ios_dpr_1") {
		t.Errorf("real iOS DPR must not trigger ios_dpr_1, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_MobileNoTouch(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["maxTouchPoints"] = 0.0
	score, reasons := reflexProbeScore(sig, probeAndroidUA)
	if !containsReason(reasons, "mobile_no_touch") {
		t.Errorf("expected mobile_no_touch, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_TouchscreenWindowsLaptopIsZero(t *testing.T) {
	// A touchscreen Windows laptop is not mobile-shaped and has real touch
	// points; must not trigger mobile_no_touch or anything else.
	sig := cleanProbeChromeSignals()
	sig["maxTouchPoints"] = 10.0
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if score != 0 {
		t.Errorf("touchscreen Windows laptop: score = %d, reasons = %v, want 0", score, reasons)
	}
}

func TestReflexProbeScore_NoWindowChrome(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["hasWindowChrome"] = false
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if !containsReason(reasons, "no_window_chrome") {
		t.Errorf("expected no_window_chrome, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_NoWindowChromeExcludesMobile(t *testing.T) {
	// Android Chrome is genuine Blink/Chromium; it is uncertain whether it
	// reliably defines window.chrome the same way desktop Chrome does, so the
	// check must not fire for mobile UAs (mirrors ios_dpr_1 / mobile_no_touch).
	sig := cleanProbeChromeSignals()
	sig["hasWindowChrome"] = false
	sig["maxTouchPoints"] = 5.0
	score, reasons := reflexProbeScore(sig, probeAndroidUA)
	if containsReason(reasons, "no_window_chrome") {
		t.Errorf("Android Chrome must not trigger no_window_chrome, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_VMWebGL(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["webglRenderer"] = "VMware, Inc. -- VMware SVGA 3D"
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if !containsReason(reasons, "vm_webgl:vmware, inc. -- vmware svga 3d") {
		t.Errorf("expected a vm_webgl reason, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_FirefoxIsUnaffectedByChromiumChecks(t *testing.T) {
	// Firefox has no userAgentData, no window.chrome, and no webdriver
	// property gate — none of the new Chromium-gated checks may fire.
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
	sig := map[string]interface{}{
		"screenW": 1920.0, "screenH": 1080.0, "innerWidth": 1900.0, "innerHeight": 950.0,
		"colorDepth": 24.0, "outerWidth": 1920.0, "languages": "en-US,en",
		"maxTouchPoints": 0.0, "hardwareConcurrency": 8.0, "deviceMemory": 8.0,
		"hasUaData": false, "webdriverPropPresent": false, "hasWindowChrome": false,
	}
	score, reasons := reflexProbeScore(sig, ua)
	if score != 0 {
		t.Errorf("Firefox 133: score = %d, reasons = %v, want 0", score, reasons)
	}
}

func TestReflexProbeScore_TZOffsetMismatch(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["tzOffsetMismatch"] = true
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if !containsReason(reasons, "tz_offset_mismatch") {
		t.Errorf("expected tz_offset_mismatch, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_TZOffsetMismatchFalseIsClean(t *testing.T) {
	// DST-boundary guard: a correctly-computed offset on either side of a
	// transition must report false and never fire, regardless of the
	// specific zone or date — this is exercised entirely client-side, so
	// the server-side test only needs to confirm the false case is inert.
	sig := cleanProbeChromeSignals()
	sig["tzOffsetMismatch"] = false
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if score != 0 {
		t.Errorf("tzOffsetMismatch=false: score = %d, reasons = %v, want 0", score, reasons)
	}
}

func TestReflexProbeScore_CanvasBlank(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["canvasBlank"] = true
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if !containsReason(reasons, "canvas_blank") {
		t.Errorf("expected canvas_blank, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_PermissionStateConflict(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["permissionConflict"] = true
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if !containsReason(reasons, "permission_state_conflict") {
		t.Errorf("expected permission_state_conflict, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexProbeScore_NativeFnTamperedRequiresTwo(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["nativeFnTamperedCount"] = 1.0
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if containsReason(reasons, "native_fn_tampered") {
		t.Errorf("a single patched API must not trigger native_fn_tampered, got score=%d reasons=%v", score, reasons)
	}
	sig["nativeFnTamperedCount"] = 2.0
	score, reasons = reflexProbeScore(sig, probeChrome131UA)
	if !containsReason(reasons, "native_fn_tampered") {
		t.Errorf("expected native_fn_tampered at count 2, got score=%d reasons=%v", score, reasons)
	}
}

func straightLinePath(n int) []interface{} {
	path := make([]interface{}, n)
	for i := 0; i < n; i++ {
		path[i] = []interface{}{float64(i * 2), float64(i), float64(i * 10)}
	}
	return path
}

func jitteryPath() []interface{} {
	return []interface{}{
		[]interface{}{0.0, 0.0, 0.0},
		[]interface{}{15.0, -8.0, 50.0},
		[]interface{}{40.0, 22.0, 100.0},
		[]interface{}{55.0, -14.0, 150.0},
		[]interface{}{80.0, 30.0, 200.0},
	}
}

func TestReflexScore_LinearMousePath(t *testing.T) {
	sig := map[string]interface{}{
		"screenW": 1920.0, "screenH": 1080.0, "languages": "en-US",
		"mouseMoved": true, "mousePath": straightLinePath(10),
		"movementDeltaSeen": true,
		// The client's own jitter computation is set to a clearly-not-jittery
		// value (well above the low_mouse_jitter guard's 2.0 threshold) so
		// this test exercises linear_mouse_path on its own: a genuinely
		// straight scripted path that the client-side jitter check did not
		// already flag. Without an explicit mouseJitter here, numVal's
		// missing-key default of 0 would be < 2.0 and the new
		// mutual-exclusivity guard (see signals.go) would suppress
		// linear_mouse_path entirely, breaking this test's intent.
		"mouseJitter": 999.0,
	}
	score, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if !containsReason(reasons, "linear_mouse_path") {
		t.Errorf("expected linear_mouse_path, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexScore_LowJitterAndLinearDragDoNotDoubleCount(t *testing.T) {
	// isLinearDrag and low_mouse_jitter both compute the same underlying
	// statistic (mean squared perpendicular deviation from the straight line
	// between the path's endpoints) from the same mousePath, just via
	// different code paths and thresholds (client-reported mouseJitter < 2.0
	// vs server-computed isLinearDrag's msd < 4.0). A straight path with the
	// client also reporting low jitter must only score low_mouse_jitter
	// (+3), never both (+6) — that combined total would reach scoreBlock (5)
	// and escalate an ordinary short, near-straight mouse movement straight
	// to the Prism drag puzzle.
	sig := map[string]interface{}{
		// Otherwise-clean signals (mirrors TestScoreSignals_CleanBehavior) so
		// only low_mouse_jitter / linear_mouse_path are in play; missing keys
		// here would default to 0 via numVal and spuriously trip unrelated
		// checks (tiny_screen, zero_avail_width, uniform_raf, ...).
		"languages":           "en-US,en",
		"screenW":             1920.0,
		"screenH":             1080.0,
		"colorDepth":          24.0,
		"outerWidth":          1920.0,
		"outerHeight":         1040.0,
		"innerHeight":         900.0,
		"maxTouchPoints":      0.0,
		"availW":              1920.0,
		"availH":              1040.0,
		"hardwareConcurrency": 8.0,
		"rafVariance":         5.0,
		"firstInteractionMs":  800.0,
		"mouseMoved":          true,
		"mousePath":           straightLinePath(10),
		"mouseJitter":         0.5,
		"velocityVariance":    999.0,
		"movementDeltaSeen":   true,
	}
	score, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if !containsReason(reasons, "low_mouse_jitter") {
		t.Errorf("expected low_mouse_jitter, got score=%d reasons=%v", score, reasons)
	}
	if containsReason(reasons, "linear_mouse_path") {
		t.Errorf("linear_mouse_path must not also fire when low_mouse_jitter already covers this path, got score=%d reasons=%v", score, reasons)
	}
	if score != 3 {
		t.Errorf("expected score 3 (low_mouse_jitter only, no double-count), got %d reasons=%v", score, reasons)
	}
}

func TestReflexScore_JitteryMousePathIsNotLinear(t *testing.T) {
	sig := map[string]interface{}{
		"screenW": 1920.0, "screenH": 1080.0, "languages": "en-US",
		"mouseMoved": true, "mousePath": jitteryPath(),
		"movementDeltaSeen": true,
	}
	_, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if containsReason(reasons, "linear_mouse_path") {
		t.Errorf("a jittery path must not trigger linear_mouse_path, got reasons=%v", reasons)
	}
}

func TestReflexScore_ZeroMovementDelta(t *testing.T) {
	sig := map[string]interface{}{
		"screenW": 1920.0, "screenH": 1080.0, "languages": "en-US",
		"mouseMoved": true, "mousePath": jitteryPath(),
		"movementDeltaSeen": false,
	}
	score, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if !containsReason(reasons, "zero_movement_delta") {
		t.Errorf("expected zero_movement_delta, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexScore_ZeroMovementDeltaGatedOnChromiumClaim(t *testing.T) {
	// MouseEvent.movementX/Y outside Pointer Lock has an inconsistent WebKit
	// (Safari) history, so zero_movement_delta must be gated on a Chromium UA
	// claim: a non-Chromium (or unparseable)
	// UA claim must skip the check entirely, never penalise it.
	sig := map[string]interface{}{
		"screenW": 1920.0, "screenH": 1080.0, "languages": "en-US",
		"mouseMoved": true, "mousePath": jitteryPath(),
		"movementDeltaSeen": false,
	}
	_, reasons := reflexScore(sig, firefoxDesktopUA, false, false)
	if containsReason(reasons, "zero_movement_delta") {
		t.Errorf("a non-Chromium UA must not trigger zero_movement_delta, got reasons=%v", reasons)
	}
}

func TestReflexScore_NoMouseMovementSkipsMovementDeltaCheck(t *testing.T) {
	// A touch-only user never moves a mouse at all; movementDeltaSeen is
	// meaningless (and false) in that case and must not be penalised.
	sig := map[string]interface{}{
		"screenW": 390.0, "screenH": 844.0, "languages": "en-US",
		"maxTouchPoints": 5.0, "mouseMoved": false, "movementDeltaSeen": false,
	}
	_, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if containsReason(reasons, "zero_movement_delta") {
		t.Errorf("touch-only user must not trigger zero_movement_delta, got reasons=%v", reasons)
	}
}

func TestReflexScore_TouchOnlyMouseMovedTrueSkipsMovementDeltaCheck(t *testing.T) {
	// Mirrors what challenge.html actually submits for a touch-only visitor:
	// its touchstart listener sets mouseMoved=true even though no real
	// mousemove ever fired, so movementDeltaSeen stays at its default false.
	// This must not trigger zero_movement_delta.
	sig := map[string]interface{}{
		"screenW": 390.0, "screenH": 844.0, "languages": "en-US",
		"maxTouchPoints": 5.0, "mouseMoved": true, "movementDeltaSeen": false,
	}
	_, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if containsReason(reasons, "zero_movement_delta") {
		t.Errorf("touch-only user (mouseMoved=true via touchstart) must not trigger zero_movement_delta, got reasons=%v", reasons)
	}
}

func TestReflexProbeScore_UniformRafGuardedByVisibility(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["rafVariance"] = 0.1
	sig["rafHidden"] = false
	sig["visibilityState"] = "visible"
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if !containsReason(reasons, "uniform_raf") {
		t.Errorf("expected uniform_raf when visible and not hidden, got score=%d reasons=%v", score, reasons)
	}
}

// Firefox rounds frame timestamps to whole milliseconds, so its 60 Hz
// cadence is always near-uniform; neither the pulse nor the click scores it.
func TestUniformRafSkippedForFirefox(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["rafVariance"] = 0.2
	sig["rafHidden"] = false
	sig["visibilityState"] = "visible"
	if _, reasons := reflexProbeScore(sig, fpFirefox133Win); containsReason(reasons, "uniform_raf") {
		t.Errorf("pulse flagged Firefox: %v", reasons)
	}
	if _, reasons := reflexScore(map[string]interface{}{"rafVariance": 0.2}, fpFirefox133Win, false, false); containsReason(reasons, "uniform_raf") {
		t.Errorf("click flagged Firefox: %v", reasons)
	}
}

func TestReflexProbeScore_UniformRafSkippedWhenHidden(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["rafVariance"] = 0.1
	sig["rafHidden"] = true
	sig["visibilityState"] = "visible"
	_, reasons := reflexProbeScore(sig, probeChrome131UA)
	if containsReason(reasons, "uniform_raf") {
		t.Errorf("a probe that was ever hidden must not trigger uniform_raf, got reasons=%v", reasons)
	}
}

func TestReflexProbeScore_UniformRafSkippedWhenNotVisible(t *testing.T) {
	sig := cleanProbeChromeSignals()
	sig["rafVariance"] = 0.1
	sig["rafHidden"] = false
	sig["visibilityState"] = "prerender"
	_, reasons := reflexProbeScore(sig, probeChrome131UA)
	if containsReason(reasons, "uniform_raf") {
		t.Errorf("a prerendered/background probe must not trigger uniform_raf, got reasons=%v", reasons)
	}
}

func TestReflexProbeScore_NoFirstInteractionChecksRemoved(t *testing.T) {
	// pulse.html has no interaction to time; firstInteractionMs is never
	// sent, so this must not be scored regardless of pageOpenMs.
	sig := cleanProbeChromeSignals()
	sig["pageOpenMs"] = 9000.0
	score, reasons := reflexProbeScore(sig, probeChrome131UA)
	if containsReason(reasons, "no_first_interaction") || containsReason(reasons, "fast_first_interaction") {
		t.Errorf("first-interaction checks must be absent from the probe scorer, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexScore_NoTaskbarHeightRemoved(t *testing.T) {
	sig := map[string]interface{}{
		"screenW": 1920.0, "screenH": 1080.0, "availH": 1080.0, "languages": "en-US",
		"maxTouchPoints": 0.0,
	}
	_, reasons := reflexScore(sig, chromeDesktopUA, false, false)
	if containsReason(reasons, "no_taskbar_height") {
		t.Errorf("no_taskbar_height must have been removed, got reasons=%v", reasons)
	}
}

// Mouse movement already in progress when the page appears is not a fast
// *decision*; only a deliberate action within 100 ms is.
func TestScoreSignals_FastMouseMoveIsNotFastInteraction(t *testing.T) {
	sig := map[string]interface{}{
		"firstInteractionMs": 30.0,
		"firstDeliberateMs":  900.0,
	}
	if _, reasons := reflexScore(sig, chromeDesktopUA, false, false); containsReason(reasons, "fast_first_interaction") {
		t.Errorf("early mouse movement scored fast_first_interaction: %v", reasons)
	}
}

func TestScoreSignals_NoBrowserChromeSkipsBrave(t *testing.T) {
	sig := map[string]interface{}{
		"outerHeight": 900.0,
		"innerHeight": 890.0,
	}
	if _, reasons := reflexScore(sig, chromeDesktopUA, false, false); !containsReason(reasons, "no_browser_chrome") {
		t.Fatalf("precondition: Chrome with 10px of chrome should score no_browser_chrome, got %v", reasons)
	}
	sig["isBrave"] = true
	if _, reasons := reflexScore(sig, chromeDesktopUA, false, false); containsReason(reasons, "no_browser_chrome") {
		t.Errorf("Brave scored no_browser_chrome: %v", reasons)
	}
}
