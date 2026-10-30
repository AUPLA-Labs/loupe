package handler

import (
	"bufio"
	"os"
	"strings"
)

// scoreProbeSignals scores passive signals collected by probe.js on real pages.
// No solve timing, mouse entropy, or scroll signals are available — only
// environment probes, rAF cadence, and first-interaction timing.
func reflexProbeScore(sig map[string]interface{}, ua string) (score int, reasons []string) {
	add := func(n int, reason string) {
		score += n
		reasons = append(reasons, reason)
	}

	claims := parseUAClaims(ua)

	touchPts := numVal(sig, "maxTouchPoints")

	// Screen
	screenW := numVal(sig, "screenW")
	screenH := numVal(sig, "screenH")
	if screenW > 0 && screenH > 0 && (screenW < 200 || screenH < 200) {
		add(3, "tiny_screen")
	}
	cd := numVal(sig, "colorDepth")
	if cd <= 1 {
		add(2, "low_color_depth")
	} else if cd < 24 && touchPts == 0 {
		add(1, "color_depth_sub24")
	}
	if screenW > 0 && touchPts == 0 && numVal(sig, "outerWidth") == 0 {
		add(3, "zero_outer_width")
	}
	if screenW > 0 && screenH > 0 {
		if numVal(sig, "innerWidth") > screenW || numVal(sig, "innerHeight") > screenH {
			// Physically impossible on a real device; headless sets a viewport
			// independent of its reported screen dimensions.
			add(4, "viewport_exceeds_screen")
		}
	}

	// Navigator
	if strVal(sig, "languages") == "" {
		add(2, "no_languages")
	}
	if boolVal(sig, "languageInconsistent") {
		add(2, "language_inconsistent")
	}
	if boolVal(sig, "platformTzMismatch") {
		add(1, "platform_tz_mismatch")
	}
	hwcRaw, hwcPresent := sig["hardwareConcurrency"]
	if hwcPresent && hwcRaw != nil {
		hwc := numVal(sig, "hardwareConcurrency")
		if hwc == 0 && touchPts == 0 {
			add(2, "zero_hw_concurrency")
		}
	}
	dm := numVal(sig, "deviceMemory")
	if dm > 0 && dm < 0.5 && touchPts == 0 {
		add(1, "low_device_memory")
	}

	// WebGL
	renderer := strings.ToLower(strVal(sig, "webglRenderer"))
	if renderer != "" {
		switch {
		case strings.Contains(renderer, "swiftshader"),
			strings.Contains(renderer, "llvmpipe"),
			strings.Contains(renderer, "softpipe"),
			strings.Contains(renderer, "virgl"):
			add(5, "headless_webgl:"+renderer)
		case strings.Contains(renderer, "mesa offscreen"),
			strings.Contains(renderer, "vmware svga"),
			strings.Contains(renderer, "microsoft basic render driver"),
			strings.Contains(renderer, "virtualbox"):
			// A VM is suggestive, not conclusive — scored below headless_webgl.
			add(3, "vm_webgl:"+renderer)
		}
	}

	// rAF cadence — skipped entirely if the tab was ever hidden or is not
	// currently visible, both of which legitimately flatten the variance.
	if rafRaw, ok := sig["rafVariance"]; ok && rafRaw != nil {
		rafVar := numVal(sig, "rafVariance")
		if rafVar < 0.5 && !boolVal(sig, "rafHidden") && strVal(sig, "visibilityState") == "visible" && !clampsFrameTimes(ua) {
			add(3, "uniform_raf")
		}
	}

	// ── Automation-framework consistency ─────────────────────────────────────
	if claims.isChromium {
		if brandVer := numVal(sig, "uaDataBrandVersion"); brandVer > 0 && int(brandVer) != claims.chromiumMajor {
			// Spoofers rewrite the UA string and forget the structured copy;
			// real Chromium keeps both in sync.
			add(5, "ua_data_mismatch")
		}
		if versionAtLeast(claims.chromiumMajor, claims.chromiumMinor, 89, 0) {
			if present, ok := sig["webdriverPropPresent"]; ok && present != nil && !boolVal(sig, "webdriverPropPresent") {
				// Chrome always defines navigator.webdriver (usually false);
				// absence of the property itself means a stealth plugin
				// deleted it — stronger evidence than the property being true.
				add(5, "webdriver_prop_deleted")
			}
		}
		if versionAtLeast(claims.chromiumMajor, claims.chromiumMinor, 90, 0) && !boolVal(sig, "hasUaData") {
			add(4, "no_ua_data")
		}
		if !claims.isMobile && !boolVal(sig, "hasWindowChrome") {
			// Android Chrome is genuine Blink/Chromium but it is uncertain whether
			// it reliably defines window.chrome the same way desktop Chrome does;
			// exclude mobile defensively rather than risk false positives on real
			// Android Chrome users (mirrors the ios_dpr_1 / mobile_no_touch guards).
			add(3, "no_window_chrome")
		}
	}
	if claims.isIOS && numVal(sig, "devicePixelRatio") == 1 {
		// Every iOS device reports a devicePixelRatio of at least 2.
		add(4, "ios_dpr_1")
	}
	if claims.isMobile && touchPts == 0 {
		add(3, "mobile_no_touch")
	}
	if boolVal(sig, "tzOffsetMismatch") {
		// Anti-detect browsers patch Date().getTimezoneOffset() and
		// Intl.DateTimeFormat's resolved zone independently, and forget to
		// keep them consistent. Computed against the actual named zone, so
		// this holds across DST.
		add(4, "tz_offset_mismatch")
	}
	if boolVal(sig, "canvasBlank") {
		// A real browser always renders something for drawn text; a headless
		// container with no fonts renders nothing. No hash is taken and no
		// identity is derived — this is a presence check, not a fingerprint.
		add(4, "canvas_blank")
	}
	if boolVal(sig, "permissionConflict") {
		// The classic headless-Chrome inconsistency: Notification.permission
		// and permissions.query({name:'notifications'}) disagree.
		add(3, "permission_state_conflict")
	}
	if numVal(sig, "nativeFnTamperedCount") >= 2 {
		// Threshold is two, not one: a single API is commonly and
		// legitimately patched by an ad blocker or privacy extension.
		add(2, "native_fn_tampered")
	}

	return
}

const (
	scoreBlock      = 5 // score >= this → escalate to puzzle CAPTCHA
	scoreSuspicious = 2 // score >= this (auto only) → escalate to manual click
)

// scoreSignals evaluates the behavioral signals sent by the challenge page.
// wasManual comes from the server-side proof challenge — true means the
// challenge was issued as a manual challenge.
// requiresManual is server-derived from the ASN — true means the IP is a
// datacenter/hosting range that must complete the manual flow.
func reflexScore(sig map[string]interface{}, ua string, wasSingleClick, requiresSingleClick bool) (score int, reasons []string) {
	add := func(n int, reason string) {
		score += n
		reasons = append(reasons, reason)
	}

	// Touch-point count is needed in multiple sections below.
	touchPts := numVal(sig, "maxTouchPoints")
	claims := parseUAClaims(ua)

	// ── Timing ───────────────────────────────────────────────────────────────
	solveMs := numVal(sig, "solveTimeMs")
	// solve_too_fast intentionally removed: the 250 ms threshold produced too
	// many false positives for legitimate users on fast LAN connections or
	// high-end CPUs. Headless bots are reliably caught by WebGL renderer,
	// zero_outer_width, and webdriver signals instead.
	if solveMs > 45*60*1000 {
		// Challenge is very stale — likely a pre-solved replay attempt.
		add(2, "solve_stale")
	}

	// ── Screen / display ────────────────────────────────────────────────────
	screenW := numVal(sig, "screenW")
	screenH := numVal(sig, "screenH")
	if screenW < 200 || screenH < 200 {
		// Real devices are never this small; headless defaults are 0 or 800×600
		// but some headless configs set tiny values.
		add(3, "tiny_screen")
	}
	// Guard with touchPts == 0: iOS Safari reports outerWidth/availWidth as 0,
	// which would falsely penalise mobile users.
	if screenW > 0 && touchPts == 0 && numVal(sig, "availW") == 0 {
		// Real desktop browsers always report availWidth; headless often returns 0.
		add(2, "zero_avail_width")
	}
	if numVal(sig, "colorDepth") <= 1 {
		add(2, "low_color_depth")
	}
	if screenW > 0 && touchPts == 0 && numVal(sig, "outerWidth") == 0 {
		// window.outerWidth is 0 in headless environments; skip mobile where it
		// is legitimately absent.
		add(3, "zero_outer_width")
	}

	// ── Window geometry ──────────────────────────────────────────────────────
	outerH := numVal(sig, "outerHeight")
	innerH := numVal(sig, "innerHeight")

	// Real browsers have ~85–100px of chrome (toolbar, address bar, tabs).
	// Headless has 0px. Skip mobile (toolbar collapses on scroll).
	// Score reduced to +2 (was +3): Firefox privacy.resistFingerprinting
	// intentionally sets outerHeight = innerHeight to prevent fingerprinting,
	// so this signal has legitimate false positives that should not be decisive.
	// Skipped entirely for Brave, whose Shields rewrite outerWidth/outerHeight
	// (observed firing on a regular, non-fullscreen Brave window).
	if outerH > 0 && innerH > 0 && touchPts == 0 && (outerH-innerH) < 50 && !boolVal(sig, "isBrave") {
		add(2, "no_browser_chrome")
	}

	// ── Navigator ────────────────────────────────────────────────────────────
	if strVal(sig, "languages") == "" {
		add(2, "no_languages")
	}

	// ── Browser API consistency ───────────────────────────────────────────────
	if boolVal(sig, "platformTzMismatch") {
		add(1, "platform_tz_mismatch")
	}

	hwcRaw, hwcPresent := sig["hardwareConcurrency"]
	if hwcPresent && hwcRaw != nil {
		hwc := numVal(sig, "hardwareConcurrency")
		if hwc == 0 && touchPts == 0 {
			add(2, "zero_hw_concurrency")
		}
	}

	// colorDepth < 24 on claimed desktop (existing check covers ≤1)
	cd := numVal(sig, "colorDepth")
	if cd > 1 && cd < 24 && touchPts == 0 {
		add(1, "color_depth_sub24")
	}

	dm := numVal(sig, "deviceMemory")
	// deviceMemory is undefined in Firefox — JSON decode gives 0 for undefined.
	// Only flag when it is explicitly very low (0.25 or 0.5 GB) on a desktop UA.
	if dm > 0 && dm < 0.5 && touchPts == 0 {
		add(1, "low_device_memory")
	}

	if boolVal(sig, "languageInconsistent") {
		add(2, "language_inconsistent")
	}

	// ── WebGL — most reliable headless indicator ─────────────────────────────
	renderer := strings.ToLower(strVal(sig, "webglRenderer"))
	if renderer != "" {
		if strings.Contains(renderer, "swiftshader") ||
			strings.Contains(renderer, "llvmpipe") ||
			strings.Contains(renderer, "softpipe") ||
			strings.Contains(renderer, "virgl") {
			add(5, "headless_webgl:"+renderer)
		}
	}

	// ── Manual challenge consistency ─────────────────────────────────────────
	if wasSingleClick {
		// The challenge was issued (server-side) as a manual challenge.
		// If signals say the user did not go through the click flow, that is
		// suspicious — the page required a click that apparently never happened.
		if !boolVal(sig, "manual") {
			add(4, "singleclick_bypass")
		}
		// A genuine user click always produces isTrusted=true. Programmatic calls
		// (console, element.click(), Playwright synthetic events) produce false.
		if !boolVal(sig, "clickTrusted") {
			add(3, "click_not_trusted")
		}
	}
	if requiresSingleClick {
		// Datacenter ASN or an escalated client: additionally verify that real
		// interaction occurred. No mouse movement and no touch on a page that
		// required a click.
		if !boolVal(sig, "mouseMoved") && touchPts == 0 {
			add(2, "no_interaction")
		}
	}

	// ── Mouse entropy ─────────────────────────────────────────────────────────
	if boolVal(sig, "mouseMoved") {
		jitter := numVal(sig, "mouseJitter")
		if jitter < 2.0 {
			if requiresSingleClick {
				// This population is already filtered down by ASN, request
				// score, and reputation before ever reaching a manual
				// challenge, and manual means the page demanded exactly one
				// deliberate physical click. A real hand doing that one
				// click still leaves this specific tremor signature; a
				// scripted click — even with randomized easing, like a
				// Playwright mouse.move()/down()/up() sequence — essentially
				// never does. Observed in production: this was the only
				// signal that fired on a bypass attempt that had already
				// suppressed navigator.webdriver, and a mere +3 here wasn't
				// enough to force the harder Prism puzzle. Weighted to
				// scoreBlock so it is sufficient on its own in this
				// population, rather than only contributing partial
				// suspicion the way it does for the broader Lumen-auto
				// population below.
				add(scoreBlock, "low_mouse_jitter_singleclick")
			} else {
				add(3, "low_mouse_jitter")
			}
		}
		velVar := numVal(sig, "velocityVariance")
		if velVar >= 0 && velVar < 0.01 {
			add(1, "uniform_velocity")
		}
		// Guard with mouseJitter >= 2.0: isLinearDrag and low_mouse_jitter both
		// compute the same underlying statistic (mean squared perpendicular
		// deviation from the straight line between the path's endpoints) from
		// the same mousePath data, just via different code paths (client-side
		// vs server-side) and different thresholds (2.0 vs 4.0). Since
		// {msd < 2.0} is a strict subset of {msd < 4.0}, without this guard
		// every path that trips low_mouse_jitter also trips linear_mouse_path,
		// double-counting a single straight/low-jitter movement as +6 instead
		// of +3. Only score linear_mouse_path in the band low_mouse_jitter
		// does not already cover.
		if isLinearDrag(sig["mousePath"]) && numVal(sig, "mouseJitter") >= 2.0 {
			// Reuses the Prism drag-path check verbatim: a mean squared
			// perpendicular deviation from the straight line between the
			// path's endpoints below 4px² indicates a scripted straight line.
			add(3, "linear_mouse_path")
		}
		// Guard with touchPts == 0: challenge.html's touchstart listener sets
		// mouseMoved=true for touch-only visitors even though no real mousemove
		// ever fired, which would otherwise leave movementDeltaSeen at its
		// default false and falsely flag a legitimate touch-only user.
		// Guard with claims.isChromium: MouseEvent.movementX/Y outside Pointer
		// Lock has an inconsistent WebKit (Safari) history, so this check is
		// gated on a UA claim: an
		// unparseable/non-Chromium claim skips the check rather than risk a
		// false positive on a real non-Chromium browser.
		if touchPts == 0 && claims.isChromium {
			if present, ok := sig["movementDeltaSeen"]; ok && present != nil && !boolVal(sig, "movementDeltaSeen") {
				// Real browsers always populate MouseEvent.movementX/Y on
				// mousemove; many synthetic event dispatch paths leave them zero.
				add(3, "zero_movement_delta")
			}
		}
	}

	// ── Scroll behavior ───────────────────────────────────────────────────────
	scrollCount := numVal(sig, "scrollCount")
	if scrollCount >= 3 {
		scrollVar := numVal(sig, "scrollIntervalVar")
		if scrollVar >= 0 && scrollVar < 500 {
			add(2, "uniform_scroll_intervals")
		}
	}
	if scrollCount == 0 && boolVal(sig, "scrollCanScroll") {
		add(1, "no_scroll_on_scrollable_page")
	}

	// ── Keystroke timing ─────────────────────────────────────────────────────
	kc := numVal(sig, "keyCount")
	ikiMax := numVal(sig, "ikiMax")
	if kc > 2 && ikiMax > 0 && ikiMax < 20 {
		add(3, "paste_or_programmatic_input")
	} else if kc == 1 && ikiMax == 0 {
		add(2, "single_keydown")
	}

	// ── rAF cadence ───────────────────────────────────────────────────────────
	rafVar := numVal(sig, "rafVariance")
	if rafVar >= 0 && rafVar < 0.5 && !boolVal(sig, "rafHidden") && !clampsFrameTimes(ua) {
		add(3, "uniform_raf")
	}

	// ── Time to first interaction ─────────────────────────────────────────────
	// fast_first_interaction only counts deliberate actions (key, touch,
	// press): mouse movement already in progress when the page appears fires
	// instantly for real users (observed on a genuine pass), but nobody can
	// decide to press something within 100 ms of a page loading.
	firstMs := numVal(sig, "firstInteractionMs")
	deliberateMs := numVal(sig, "firstDeliberateMs")
	pageOpenMs := numVal(sig, "pageOpenMs")
	if deliberateMs > 0 && deliberateMs < 100 {
		add(2, "fast_first_interaction")
	}
	if firstMs == 0 && pageOpenMs > 5000 {
		add(1, "no_first_interaction")
	}

	return
}

// ── Known bot/tool UA patterns ───────────────────────────────────────────────

// defaultBotUAPatterns ships as a baseline regardless of config, so removing
// the (optional) bad_bot_uas config section never weakens this check.
var defaultBotUAPatterns = append(httpClientUAPatterns, scannerUAPatterns...)

// httpClientUAPatterns are HTTP client libraries: never a browser, but what
// a legitimate API client sends, so api routes let them through.
var httpClientUAPatterns = []string{
	"curl/", "wget/",
	"python-requests", "python-urllib", "python/",
	"go-http-client/",
	"java/", "jakarta commons-httpclient", "apache-httpclient",
	"libwww-perl/",
	"ruby/",
	"okhttp/", "retrofit/",
	"axios/", "node-fetch/", "node-http/", "got/", "superagent/",
	"aiohttp/", "httpx/",
}

// scannerUAPatterns are scrapers, scanners and automation, refused
// everywhere, api routes included.
var scannerUAPatterns = []string{
	"scrapy/", "mechanize",
	"masscan", "zgrab", "nikto", "nuclei/", "sqlmap",
	"dirbuster", "gobuster", "feroxbuster",
	"nmap scripting", "wfuzz", "ffuf/",
	"semrush", "ahrefsbot", "dotbot", "mj12bot",
	// No real browser ever identifies itself as headless. Playwright's and
	// Puppeteer's default Chromium launch (headless: true, the common case
	// for scripted automation) puts this literal token in its own UA.
	"headless",
}

// isKnownBotUA returns true for UAs that are definitively automation tools
// or scanners, never legitimate human browsers. extra is merged in from
// config (bad_bot_uas.patterns / patterns_file) so new patterns can be added
// without a rebuild.
// clampsFrameTimes reports a browser whose rAF timestamps are rounded to
// whole milliseconds (Firefox's reduceTimerPrecision; resistFingerprinting
// rounds coarser still). At 60 Hz its frame intervals alternate 16/17 ms, a
// variance near 0.2 that reads as uniform_raf on every real Firefox. A
// Chromium bot claiming Firefox to get this exemption is caught by the
// fingerprint's engine_mismatch instead.
func clampsFrameTimes(ua string) bool {
	return strings.Contains(ua, "Firefox/")
}

func isKnownBotUA(ua string, extra []string) bool {
	if ua == "" {
		return true
	}
	lower := strings.ToLower(ua)
	for _, p := range defaultBotUAPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	for _, p := range extra {
		if p != "" && strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// isScannerUA is isKnownBotUA for an api route: HTTP client libraries and
// an empty User-Agent are expected there, scanners and configured patterns
// are still refused.
func isScannerUA(ua string, extra []string) bool {
	lower := strings.ToLower(ua)
	for _, p := range scannerUAPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	for _, p := range extra {
		if p != "" && strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// loadUAPatternsFile parses one lowercase-folded substring per line. Blank
// lines and lines starting with '#' are ignored — same convention as the ASN
// list file.
func loadUAPatternsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, strings.ToLower(line))
	}
	return patterns, sc.Err()
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func numVal(m map[string]interface{}, key string) float64 {
	v, _ := m[key]
	return toFloat(v)
}

func toFloat(v interface{}) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	}
	return 0
}

func strVal(m map[string]interface{}, key string) string {
	s, _ := m[key].(string)
	return s
}

func boolVal(m map[string]interface{}, key string) bool {
	b, _ := m[key].(bool)
	return b
}

// isConclusiveAutomation reports whether signals contain proof of
// automation tooling strong enough to block outright, with no scoring
// involved — navigator.webdriver and the automation-artifact sweep receive
// identical treatment, since both are properties no real browser exposes.
func isConclusiveAutomation(signals map[string]interface{}) bool {
	return boolVal(signals, "webdriver") || boolVal(signals, "automationArtifact")
}

// conclusiveAutomationReason names which of the two conclusive checks fired,
// for the events log. webdriver is checked first only for stable ordering
// when both happen to be true.
func conclusiveAutomationReason(signals map[string]interface{}) string {
	if boolVal(signals, "webdriver") {
		return "pulse_webdriver"
	}
	return "pulse_automation_artifact"
}

// reflexPrismScore evaluates behavioral signals submitted with the Prism CAPTCHA.
// webdriver is handled by the caller as an instant block and is not scored here.
func reflexPrismScore(sig map[string]interface{}) (score int, reasons []string) {
	add := func(n int, reason string) {
		score += n
		reasons = append(reasons, reason)
	}

	screenW := numVal(sig, "screenW")
	screenH := numVal(sig, "screenH")
	if screenW < 200 || screenH < 200 {
		add(3, "tiny_screen")
	}
	if strVal(sig, "languages") == "" {
		add(2, "no_languages")
	}

	dragDuration := numVal(sig, "dragDuration")
	if dragDuration > 0 && dragDuration < 150 {
		add(3, "too_fast_drag")
	}

	preDragTime := numVal(sig, "preDragTime")
	if preDragTime > 0 && preDragTime < 400 {
		add(2, "instant_drag")
	}

	if numVal(sig, "attempts") == 0 {
		add(2, "no_drag_attempt")
	}

	if isLinearDrag(sig["dragPath"]) {
		add(2, "linear_drag")
	}

	return
}

// isLinearDrag returns true when the mean squared perpendicular deviation of
// the drag path from the straight line between start and end is < 4px²,
// indicating a scripted straight-line drag.
func isLinearDrag(raw interface{}) bool {
	path, ok := raw.([]interface{})
	if !ok || len(path) < 3 {
		return false
	}

	type pt struct{ x, y float64 }
	pts := make([]pt, 0, len(path))
	for _, entry := range path {
		arr, ok := entry.([]interface{})
		if !ok || len(arr) < 2 {
			continue
		}
		pts = append(pts, pt{toFloat(arr[0]), toFloat(arr[1])})
	}
	if len(pts) < 3 {
		return false
	}

	x0, y0 := pts[0].x, pts[0].y
	x1, y1 := pts[len(pts)-1].x, pts[len(pts)-1].y
	dx, dy := x1-x0, y1-y0
	lenSq := dx*dx + dy*dy
	if lenSq == 0 {
		return false
	}

	var sumSq float64
	for _, p := range pts[1 : len(pts)-1] {
		cross := (p.x-x0)*dy - (p.y-y0)*dx
		sumSq += (cross * cross) / lenSq
	}
	msd := sumSq / float64(len(pts)-2)
	return msd < 4.0
}
