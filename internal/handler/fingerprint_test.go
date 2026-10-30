package handler

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	fpChrome126Linux = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	fpChrome126Win   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	fpFirefox133Win  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
	fpSafari18Mac    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
	fpIPhone17       = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/122.0.6261.89 Mobile/15E148 Safari/604.1"
	fpAndroid131     = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
)

func fpRequest(ua string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/loupe/pulse/verify", nil)
	r.Header.Set("User-Agent", ua)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// fpWith returns the clean Chrome-on-Linux fixture with edit applied.
func fpWith(t *testing.T, edit func(m map[string]interface{})) map[string]interface{} {
	t.Helper()
	m := cleanFP(t)
	if edit != nil {
		edit(m)
	}
	return m
}

func sub(m map[string]interface{}, key string) map[string]interface{} {
	return m[key].(map[string]interface{})
}

func scoreFP(t *testing.T, fp interface{}, ua string, headers map[string]string) []string {
	t.Helper()
	_, reasons := reflexFingerprintScore(fp, fpRequest(ua, headers))
	return reasons
}

func TestFingerprint_CleanChromeScoresZero(t *testing.T) {
	score, reasons := reflexFingerprintScore(cleanFP(t), fpRequest(fpChrome126Linux, map[string]string{"Accept-Language": "en-US,en;q=0.9"}))
	if score != 0 || len(reasons) != 0 {
		t.Errorf("clean fingerprint scored %d %v", score, reasons)
	}
}

func TestFingerprint_Incomplete(t *testing.T) {
	if r := scoreFP(t, nil, fpChrome126Linux, nil); !contains(r, "fp_incomplete") {
		t.Errorf("missing fp: %v", r)
	}
	fp := fpWith(t, func(m map[string]interface{}) { delete(m, "integrity") })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "fp_incomplete") {
		t.Errorf("missing sync section: %v", r)
	}
	// Async sections may be late (null) — never incomplete.
	fp = fpWith(t, func(m map[string]interface{}) { m["gpu"], m["audio"], m["voices"] = nil, nil, nil })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); contains(r, "fp_incomplete") {
		t.Errorf("null async sections flagged: %v", r)
	}
}

func TestFingerprint_EngineMismatch(t *testing.T) {
	firefoxEngine := map[string]interface{}{"err": "o is null", "v8stack": false, "moz": true, "evalLen": 37.0}
	safariEngine := map[string]interface{}{"err": "null is not an object (evaluating 'o.x')", "v8stack": false, "moz": false, "evalLen": 33.0}

	// Chrome UA, Gecko engine: a spoofed UA.
	fp := fpWith(t, func(m map[string]interface{}) { m["engine"] = firefoxEngine })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "engine_mismatch") {
		t.Errorf("chrome UA on gecko: %v", r)
	}
	// Chrome on iOS is WebKit — no mismatch.
	fp = fpWith(t, func(m map[string]interface{}) { m["engine"] = safariEngine; m["features"] = map[string]interface{}{} })
	if r := scoreFP(t, fp, fpIPhone17, nil); contains(r, "engine_mismatch") {
		t.Errorf("CriOS on JSC flagged: %v", r)
	}
	// Internet Explorer and EdgeHTML can't run the page at all, so any
	// engine behind those claims is a spoofed UA — including a Chromium one
	// behind legacy Edge's "Chrome/" token.
	ie11 := "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko"
	edge18 := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362"
	fp = fpWith(t, func(m map[string]interface{}) { m["engine"] = firefoxEngine })
	if r := scoreFP(t, fp, ie11, nil); !contains(r, "engine_mismatch") {
		t.Errorf("IE11 UA on gecko: %v", r)
	}
	fp = fpWith(t, func(map[string]interface{}) {})
	if r := scoreFP(t, fp, edge18, nil); !contains(r, "engine_mismatch") {
		t.Errorf("EdgeHTML UA on v8: %v", r)
	}
	// Probes that disagree with each other classify as nothing.
	fp = fpWith(t, func(m map[string]interface{}) {
		m["engine"] = map[string]interface{}{"err": "o is null", "v8stack": true, "moz": true}
	})
	if r := scoreFP(t, fp, fpChrome126Linux, nil); contains(r, "engine_mismatch") {
		t.Errorf("inconsistent probes flagged: %v", r)
	}
}

func TestFingerprint_FeatureVersionMismatch(t *testing.T) {
	setFeat := func(vals map[string]bool) func(m map[string]interface{}) {
		return func(m map[string]interface{}) {
			f := sub(m, "features")
			for k, v := range vals {
				f[k] = v
			}
		}
	}
	// Chrome 126 claim, engine lacks two features from Chrome <=124.
	fp := fpWith(t, setFeat(map[string]bool{"groupBy": false, "setUnion": false}))
	if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "feature_version_mismatch") {
		t.Errorf("old engine behind new UA: %v", r)
	}
	// One missing feature is not enough.
	fp = fpWith(t, setFeat(map[string]bool{"groupBy": false}))
	if r := scoreFP(t, fp, fpChrome126Linux, nil); contains(r, "feature_version_mismatch") {
		t.Errorf("single missing feature flagged: %v", r)
	}
	// Features from Chrome 136 on a Chrome 126 claim: newer engine, old UA.
	fp = fpWith(t, setFeat(map[string]bool{"regexpEscape": true, "promiseTry": true}))
	if r := scoreFP(t, fp, fpChrome126Linux, nil); contains(r, "feature_version_mismatch") {
		// promiseTry (128) is within the margin; only regexpEscape counts.
		t.Errorf("one early feature flagged: %v", r)
	}
	old := strings.Replace(fpChrome126Linux, "Chrome/126", "Chrome/110", 1)
	fp = fpWith(t, setFeat(map[string]bool{"regexpEscape": true, "promiseTry": true}))
	if r := scoreFP(t, fp, old, nil); !contains(r, "feature_version_mismatch") {
		t.Errorf("chrome 110 claim with 128/136 features: %v", r)
	}
	// Feature absent near its release (within margin) is fine.
	just := strings.Replace(fpChrome126Linux, "Chrome/126", "Chrome/123", 1)
	fp = fpWith(t, setFeat(map[string]bool{"setUnion": false, "iterHelpers": false}))
	if r := scoreFP(t, fp, just, nil); contains(r, "feature_version_mismatch") {
		t.Errorf("features within margin flagged: %v", r)
	}
}

func TestFingerprint_WorkerAndIframe(t *testing.T) {
	fp := fpWith(t, func(m map[string]interface{}) { sub(m, "worker")["platform"] = "Win32" })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "worker_ua_mismatch") {
		t.Errorf("worker platform differs: %v", r)
	}
	fp = fpWith(t, func(m map[string]interface{}) { sub(m, "iframe")["hc"] = 4.0 })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "iframe_nav_mismatch") {
		t.Errorf("iframe hc differs: %v", r)
	}
	// Brave farbles hardwareConcurrency per realm.
	fp = fpWith(t, func(m map[string]interface{}) { sub(m, "iframe")["hc"] = 4.0; sub(m, "nav")["brave"] = true })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); contains(r, "iframe_nav_mismatch") {
		t.Errorf("brave hc farbling flagged: %v", r)
	}
	// Main-thread PoW fallback: no worker values, nothing to compare.
	fp = fpWith(t, func(m map[string]interface{}) { m["worker"] = nil })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); contains(r, "worker_ua_mismatch") {
		t.Errorf("absent worker flagged: %v", r)
	}
}

func TestFingerprint_UAHeaderMismatch(t *testing.T) {
	fp := fpWith(t, func(m map[string]interface{}) { sub(m, "nav")["ua"] = fpFirefox133Win })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "ua_header_mismatch") {
		t.Errorf("%v", r)
	}
	fp = fpWith(t, func(m map[string]interface{}) {
		sub(m, "nav")["ua"] = fpChrome126Linux
		sub(m, "iframe")["ua"] = fpChrome126Linux
		sub(m, "worker")["ua"] = fpChrome126Linux
	})
	if r := scoreFP(t, fp, fpChrome126Linux, nil); len(r) != 0 {
		t.Errorf("matching UA scored %v", r)
	}
}

func TestFingerprint_UACH(t *testing.T) {
	uach := func(platform string, mobile bool, chromium string) func(m map[string]interface{}) {
		return func(m map[string]interface{}) {
			m["uach"] = map[string]interface{}{"platform": platform, "mobile": mobile,
				"fullVersionList": []interface{}{"Chromium/" + chromium, "Google Chrome/" + chromium}}
		}
	}
	if r := scoreFP(t, fpWith(t, uach("Linux", false, "126.0.6478.126")), fpChrome126Linux,
		map[string]string{"Sec-CH-UA-Platform": `"Linux"`}); contains(r, "uach_mismatch") {
		t.Errorf("consistent hints flagged: %v", r)
	}
	for name, c := range map[string]struct {
		edit    func(m map[string]interface{})
		headers map[string]string
	}{
		"platform": {uach("Windows", false, "126.0.1.2"), nil},
		"version":  {uach("Linux", false, "120.0.1.2"), nil},
		"mobile":   {uach("Linux", true, "126.0.1.2"), nil},
		"header":   {uach("Linux", false, "126.0.1.2"), map[string]string{"Sec-CH-UA-Platform": `"Windows"`}},
	} {
		if r := scoreFP(t, fpWith(t, c.edit), fpChrome126Linux, c.headers); !contains(r, "uach_mismatch") {
			t.Errorf("%s mismatch not flagged: %v", name, r)
		}
	}
	// Android tablets omit "Mobile" from the UA; mobile is not compared there.
	tablet := strings.Replace(fpAndroid131, " Mobile", "", 1)
	fp := fpWith(t, func(m map[string]interface{}) {
		uach("Android", false, "131.0.1.2")(m)
		sub(m, "mq")["pointerCoarse"], sub(m, "mq")["anyCoarse"] = true, true
		sub(m, "nav")["maxTouchPoints"] = 5.0
		m["features"] = map[string]interface{}{}
	})
	if r := scoreFP(t, fp, tablet, nil); contains(r, "uach_mismatch") {
		t.Errorf("android tablet flagged: %v", r)
	}
}

func TestFingerprint_Integrity(t *testing.T) {
	fp := fpWith(t, func(m map[string]interface{}) {
		sub(m, "integrity")["getterNoThrow"] = []interface{}{"webdriver", "platform"}
	})
	if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "getter_receiver_tampered") {
		t.Errorf("%v", r)
	}
	fp = fpWith(t, func(m map[string]interface{}) { sub(m, "integrity")["getterNoThrow"] = []interface{}{"webdriver"} })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); contains(r, "getter_receiver_tampered") {
		t.Errorf("one patched getter (an extension) flagged: %v", r)
	}
	fp = fpWith(t, func(m map[string]interface{}) { sub(m, "integrity")["navOwnProps"] = []interface{}{"webdriver"} })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "own_prop_on_navigator") {
		t.Errorf("%v", r)
	}
	// Brave, AdGuard, Ghostery, Privacy Badger and DuckDuckGo.
	for _, p := range []string{"brave", "getBattery", "privateAttribution", "globalPrivacyControl", "doNotTrack", "duckduckgo"} {
		fp = fpWith(t, func(m map[string]interface{}) { sub(m, "integrity")["navOwnProps"] = []interface{}{p} })
		if r := scoreFP(t, fp, fpChrome126Linux, nil); contains(r, "own_prop_on_navigator") {
			t.Errorf("privacy tool's navigator.%s flagged: %v", p, r)
		}
	}
	// What spoofers such as Chameleon patch is still flagged, alongside an
	// exempt name too.
	for _, p := range []string{"languages", "plugins", "hardwareConcurrency"} {
		fp = fpWith(t, func(m map[string]interface{}) {
			sub(m, "integrity")["navOwnProps"] = []interface{}{"globalPrivacyControl", p}
		})
		if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "own_prop_on_navigator") {
			t.Errorf("spoofed navigator.%s not flagged: %v", p, r)
		}
	}
	fp = fpWith(t, func(m map[string]interface{}) { sub(m, "integrity")["toStringNative"] = false })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "toString_proxy") {
		t.Errorf("%v", r)
	}
}

func TestFingerprint_GPUMismatch(t *testing.T) {
	d3d := "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)"
	fp := fpWith(t, func(m map[string]interface{}) { sub(m, "webgl")["renderer"] = d3d })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "gpu_mismatch") {
		t.Errorf("D3D on Linux: %v", r)
	}
	fp = fpWith(t, func(m map[string]interface{}) {
		sub(m, "webgl")["renderer"] = d3d
		m["fonts"] = []interface{}{"Segoe UI", "Calibri", "Consolas"}
	})
	if r := scoreFP(t, fp, fpChrome126Win, nil); contains(r, "gpu_mismatch") {
		t.Errorf("D3D on Windows flagged: %v", r)
	}
	fp = fpWith(t, func(m map[string]interface{}) {
		m["gpu"] = map[string]interface{}{"vendor": "apple", "architecture": "metal-3"}
	})
	if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "gpu_mismatch") {
		t.Errorf("Apple WebGPU adapter on Linux: %v", r)
	}
	// Differing WebGL/WebGPU vendors (hybrid GPU laptops) are not scored.
	fp = fpWith(t, func(m map[string]interface{}) { m["gpu"] = map[string]interface{}{"vendor": "nvidia"} })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); contains(r, "gpu_mismatch") {
		t.Errorf("hybrid GPU flagged: %v", r)
	}
}

func TestFingerprint_FontOSMismatch(t *testing.T) {
	win := func(fonts ...interface{}) map[string]interface{} {
		return fpWith(t, func(m map[string]interface{}) { m["fonts"] = fonts })
	}
	if r := scoreFP(t, win("Arial", "DejaVu Sans"), fpChrome126Win, nil); !contains(r, "font_os_mismatch") {
		t.Errorf("Windows claim without Windows fonts: %v", r)
	}
	if r := scoreFP(t, win("Segoe UI", "Calibri", "Arial"), fpChrome126Win, nil); contains(r, "font_os_mismatch") {
		t.Errorf("one core font missing flagged: %v", r)
	}
	if r := scoreFP(t, win("Arial", "DejaVu Sans"), fpChrome126Linux, nil); contains(r, "font_os_mismatch") {
		t.Errorf("Linux has no font rule: %v", r)
	}
	// Firefox resistFingerprinting: bundled fonts, UTC.
	rfp := fpWith(t, func(m map[string]interface{}) {
		m["fonts"] = []interface{}{"Arial"}
		sub(m, "intl")["timeZone"] = "UTC"
		m["engine"] = map[string]interface{}{"err": "o is null", "v8stack": false, "moz": true}
		m["features"] = map[string]interface{}{}
	})
	if r := scoreFP(t, rfp, fpFirefox133Win, nil); contains(r, "font_os_mismatch") {
		t.Errorf("Firefox RFP flagged: %v", r)
	}
}

func TestUnverifiableReadout(t *testing.T) {
	readout := func(fp interface{}, ua string, headers map[string]string) string {
		t.Helper()
		return unverifiableReadout(fp, fpRequest(ua, headers))
	}
	if r := readout(cleanFP(t), fpChrome126Linux, nil); r != "" {
		t.Errorf("clean fingerprint: %q", r)
	}

	// Two renders in one page that differ: something randomises readouts,
	// whatever the browser claims to be.
	canvasNoise := func(m map[string]interface{}) { m["canvas"] = []interface{}{"aaaa", "bbbb"} }
	audioNoise := func(m map[string]interface{}) { m["audio"] = []interface{}{"124.04", "124.05"} }
	for _, ua := range []string{fpChrome126Linux, fpFirefox133Win} {
		if r := readout(fpWith(t, canvasNoise), ua, nil); r != "readout_noise" {
			t.Errorf("canvas noise on %s: %q", ua, r)
		}
		if r := readout(fpWith(t, audioNoise), ua, nil); r != "readout_noise" {
			t.Errorf("audio noise on %s: %q", ua, r)
		}
	}
	// Brave and Safari add noise by default, with nothing to turn off.
	brave := fpWith(t, func(m map[string]interface{}) { canvasNoise(m); sub(m, "nav")["brave"] = true })
	if r := readout(brave, fpChrome126Linux, nil); r != "" {
		t.Errorf("Brave: %q", r)
	}
	if r := readout(fpWith(t, canvasNoise), fpChrome126Linux, map[string]string{"Sec-CH-UA": `"Brave";v="141", "Chromium";v="141"`}); r != "" {
		t.Errorf("Brave via client hints: %q", r)
	}
	if r := readout(fpWith(t, audioNoise), fpSafari18Mac, nil); r != "" {
		t.Errorf("Safari: %q", r)
	}

	// Blocked: no canvas readback at all, or a solid fill read back blank.
	if r := readout(fpWith(t, func(m map[string]interface{}) { m["canvas"] = []interface{}{nil, nil} }), fpChrome126Linux, nil); r != "readout_blocked" {
		t.Errorf("no canvas: %q", r)
	}
	for _, px := range [][]interface{}{{0.0, 0.0, 0.0, 0.0}, {255.0, 255.0, 255.0, 255.0}} {
		fp := fpWith(t, func(m map[string]interface{}) { m["canvasPx"] = px })
		if r := readout(fp, fpChrome126Linux, nil); r != "readout_blocked" {
			t.Errorf("pixel %v: %q", px, r)
		}
	}
	if r := readout(fpWith(t, func(m map[string]interface{}) { m["canvasPx"] = []interface{}{255.0, 102.0, 0.0, 255.0} }), fpChrome126Linux, nil); r != "" {
		t.Errorf("orange pixel: %q", r)
	}

	// An incomplete fingerprint is the scorer's fp_incomplete, not this.
	if r := readout(fpWith(t, func(m map[string]interface{}) { delete(m, "integrity"); canvasNoise(m) }), fpChrome126Linux, nil); r != "" {
		t.Errorf("incomplete: %q", r)
	}
}

func TestFingerprint_AcceptLanguage(t *testing.T) {
	if r := scoreFP(t, cleanFP(t), fpChrome126Linux, map[string]string{"Accept-Language": "de-DE,de;q=0.9"}); !contains(r, "accept_language_mismatch") {
		t.Errorf("%v", r)
	}
	if r := scoreFP(t, cleanFP(t), fpChrome126Linux, map[string]string{"Accept-Language": "en"}); contains(r, "accept_language_mismatch") {
		t.Errorf("same primary language flagged: %v", r)
	}
}

func TestFingerprint_Voices(t *testing.T) {
	voices := func(vs ...[]interface{}) map[string]interface{} {
		return fpWith(t, func(m map[string]interface{}) {
			l := make([]interface{}, len(vs))
			for i, v := range vs {
				l[i] = v
			}
			m["voices"] = l
			m["engine"] = map[string]interface{}{"err": "null is not an object (evaluating 'o.x')", "v8stack": false, "moz": false}
			m["features"] = map[string]interface{}{}
			m["fonts"] = []interface{}{"Helvetica Neue", "Menlo", "Apple SD Gothic Neo"}
		})
	}
	zira := []interface{}{"Microsoft Zira - English (United States)", "Microsoft Zira - English (United States)", true, "en-US"}
	online := []interface{}{"Microsoft Aria Online (Natural) - English (United States)", "x", false, "en-US"}
	samantha := []interface{}{"Samantha", "com.apple.voice.compact.en-US.Samantha", true, "en-US"}
	if r := scoreFP(t, voices(zira), fpSafari18Mac, nil); !contains(r, "voices_os_mismatch") {
		t.Errorf("Windows voice on macOS: %v", r)
	}
	if r := scoreFP(t, voices(samantha, online), fpSafari18Mac, nil); contains(r, "voices_os_mismatch") {
		t.Errorf("Edge online voice on macOS flagged: %v", r)
	}
	if r := scoreFP(t, voices(), fpSafari18Mac, nil); !contains(r, "voices_os_mismatch") {
		t.Errorf("known-zero voices on macOS Safari: %v", r)
	}
	// null = not known by the deadline: never scored.
	fp := fpWith(t, func(m map[string]interface{}) { m["voices"] = nil })
	if r := scoreFP(t, fp, fpChrome126Win, nil); contains(r, "voices_os_mismatch") {
		t.Errorf("late voices flagged: %v", r)
	}
}

func TestFingerprint_PointerTouch(t *testing.T) {
	fp := fpWith(t, func(m map[string]interface{}) { sub(m, "mq")["pointerCoarse"] = true })
	if r := scoreFP(t, fp, fpChrome126Linux, nil); !contains(r, "pointer_touch_mismatch") {
		t.Errorf("coarse pointer without touch points: %v", r)
	}
	// Phone UA with only a fine pointer: mobile emulation by UA string alone.
	phone := fpWith(t, func(m map[string]interface{}) {
		sub(m, "nav")["maxTouchPoints"] = 5.0
		m["features"] = map[string]interface{}{}
	})
	if r := scoreFP(t, phone, fpAndroid131, nil); !contains(r, "pointer_touch_mismatch") {
		t.Errorf("phone without coarse pointer: %v", r)
	}
	// Touchscreen laptop: coarse available, touch points reported.
	laptop := fpWith(t, func(m map[string]interface{}) {
		sub(m, "mq")["anyCoarse"] = true
		sub(m, "nav")["maxTouchPoints"] = 10.0
	})
	if r := scoreFP(t, laptop, fpChrome126Linux, nil); contains(r, "pointer_touch_mismatch") {
		t.Errorf("touchscreen laptop flagged: %v", r)
	}
}

func TestFingerprint_DevicesAndCDP(t *testing.T) {
	fp := fpWith(t, func(m map[string]interface{}) {
		m["devices"] = map[string]interface{}{"audioinput": 0.0, "audiooutput": 0.0, "videoinput": 0.0}
		m["cdp"] = true
	})
	score, reasons := reflexFingerprintScore(fp, fpRequest(fpChrome126Linux, nil))
	if !contains(reasons, "no_media_devices") || !contains(reasons, "cdp_runtime_leak") {
		t.Errorf("%v", reasons)
	}
	if score != 1 {
		t.Errorf("score = %d, want 1 (cdp_runtime_leak is log-only)", score)
	}
}

func TestFingerprintHashes(t *testing.T) {
	h := fingerprintHashes(cleanFP(t))
	for _, k := range []string{"canvas", "webgl", "webgl_render", "audio", "fonts", "media", "engine", "features", "screen", "nav", "intl"} {
		if len(h[k]) != 12 {
			t.Errorf("hash %q = %q, want 12 hex chars", k, h[k])
		}
	}
	again := fingerprintHashes(fpWith(t, func(m map[string]interface{}) {
		m["fonts"] = []interface{}{"Liberation Sans", "Arial", "DejaVu Sans"} // reordered
	}))
	if again["fonts"] != h["fonts"] {
		t.Error("font hash must not depend on order")
	}
	if fingerprintHashes(nil) != nil {
		t.Error("no fingerprint must yield nil")
	}
}

// fingerprint.js and the Go tables must agree on feature ids and on the
// synchronous section keys.
func TestFingerprintJSMatchesGoTables(t *testing.T) {
	src, err := staticFiles.ReadFile("fingerprint.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)

	body := js[strings.Index(js, "function features() {"):]
	body = body[strings.Index(body, "return {"):strings.Index(body, "    };\n  }")]
	re := regexp.MustCompile(`(?m)^\s+([A-Za-z]\w*):`)
	var got []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		got = append(got, m[1])
	}
	sort.Strings(got)
	var want []string
	for id := range featureIntros {
		want = append(want, id)
	}
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("fingerprint.js features %v\nfeatureIntros %v", got, want)
	}

	collect := js[strings.Index(js, "var fp = {"):]
	collect = collect[:strings.Index(collect, "};")]
	for _, k := range fpRequiredKeys {
		if !regexp.MustCompile(`\b` + k + `:`).MatchString(collect) {
			t.Errorf("fingerprint.js collect() never sends required key %q", k)
		}
	}
}
