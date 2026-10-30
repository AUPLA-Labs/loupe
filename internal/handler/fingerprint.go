package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/AUPLA-Labs/loupe/internal/cookie"
)

// Fingerprint scoring. fingerprint.js
// collects raw values from every browser API it can reach; this file scores
// contradictions between them, the UA claim, and the request headers, and
// reduces each surface to a short component hash for the events log and the
// cluster keys (clusterkeys.go). Raw values are never stored.
//
// Like every other scored signal, these only choose how hard a challenge
// is. Each check compares the client with itself and is gated on the claim
// it would contradict, so an unparseable claim or an absent value scores
// nothing.

type fpNav struct {
	UA             string   `json:"ua"`
	Platform       string   `json:"platform"`
	HC             *float64 `json:"hc"`
	Langs          string   `json:"langs"`
	MaxTouchPoints float64  `json:"maxTouchPoints"`
	Brave          bool     `json:"brave"`
}

type fingerprint struct {
	Canvas   []*string `json:"canvas"`
	CanvasPx []float64 `json:"canvasPx"`
	WebGL    *struct {
		Vendor   *string         `json:"vendor"`
		Renderer *string         `json:"renderer"`
		Params   json.RawMessage `json:"params"`
		Ext      []string        `json:"ext"`
		Prec     json.RawMessage `json:"prec"`
		Render   *string         `json:"render"`
	} `json:"webgl"`
	Fonts  []string `json:"fonts"`
	Engine *struct {
		Err     string  `json:"err"`
		V8Stack bool    `json:"v8stack"`
		Moz     bool    `json:"moz"`
		EvalLen float64 `json:"evalLen"`
	} `json:"engine"`
	Features map[string]bool `json:"features"`
	Intl     *struct {
		Languages []string `json:"languages"`
		Locale    string   `json:"locale"`
		TimeZone  string   `json:"timeZone"`
	} `json:"intl"`
	MQ *struct {
		PointerCoarse *bool `json:"pointerCoarse"`
		AnyCoarse     *bool `json:"anyCoarse"`
	} `json:"mq"`
	Codecs    json.RawMessage `json:"codecs"`
	Nav       *fpNav          `json:"nav"`
	Screen    json.RawMessage `json:"screen"`
	Iframe    *fpNav          `json:"iframe"`
	Integrity *struct {
		GetterNoThrow  []string `json:"getterNoThrow"`
		NavOwnProps    []string `json:"navOwnProps"`
		ToStringNative bool     `json:"toStringNative"`
	} `json:"integrity"`
	CDP bool `json:"cdp"`
	GPU *struct {
		Vendor       string `json:"vendor"`
		Architecture string `json:"architecture"`
	} `json:"gpu"`
	Audio []*string `json:"audio"`
	UACH  *struct {
		Platform        string   `json:"platform"`
		Mobile          bool     `json:"mobile"`
		FullVersionList []string `json:"fullVersionList"`
	} `json:"uach"`
	Voices  [][]interface{}    `json:"voices"`
	Devices map[string]float64 `json:"devices"`
	Worker  *fpNav             `json:"worker"`
}

// fpRequiredKeys are the synchronous sections fingerprint.js always sends.
// Missing any of them means the page's collector never ran.
var fpRequiredKeys = []string{"canvas", "webgl", "fonts", "engine", "features", "intl",
	"mq", "nav", "screen", "iframe", "integrity"}

// parseFingerprint decodes the sealed "fp" signal. complete is false when
// the object or any synchronous section key is missing.
func parseFingerprint(raw interface{}) (fp *fingerprint, complete bool) {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil, false
	}
	complete = true
	for _, k := range fpRequiredKeys {
		if _, ok := m[k]; !ok {
			complete = false
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, false
	}
	fp = &fingerprint{}
	if err := json.Unmarshal(b, fp); err != nil {
		return nil, false
	}
	return fp, complete
}

// featureIntro is the first release that shipped a feature, per engine.
// Safari versions are major + minor/10 (17.4 → 17.4).
type featureIntro struct {
	chrome, firefox int
	safari          float64
}

// featureIntros must list exactly the ids fingerprint.js features() sends.
var featureIntros = map[string]featureIntro{
	"findLast":           {97, 104, 15.4},
	"hasOwn":             {93, 92, 15.4},
	"structuredClone":    {98, 94, 15.4},
	"at":                 {92, 90, 15.4},
	"toSorted":           {110, 115, 16.0},
	"fromAsync":          {121, 115, 16.4},
	"withResolvers":      {119, 121, 17.4},
	"groupBy":            {117, 119, 17.4},
	"setUnion":           {122, 127, 17.0},
	"iterHelpers":        {122, 131, 18.4},
	"regexpEscape":       {136, 134, 18.2},
	"promiseTry":         {128, 134, 18.2},
	"cssHas":             {105, 121, 15.4},
	"cssContainer":       {105, 110, 16.0},
	"cssOklch":           {111, 113, 15.4},
	"cssTextWrapBalance": {114, 121, 17.5},
}

// Core system fonts per OS: a desktop claiming the OS while missing two or
// more of its trio is not running that OS.
var (
	windowsCoreFonts = []string{"Segoe UI", "Calibri", "Consolas"}
	macCoreFonts     = []string{"Helvetica Neue", "Menlo", "Apple SD Gothic Neo"}
	macOnlyFonts     = []string{"Apple SD Gothic Neo", "Hiragino Sans", "PingFang SC", "Apple Color Emoji"}
	windowsOnlyFonts = []string{"Segoe UI", "Segoe UI Emoji", "Malgun Gothic", "Microsoft YaHei"}
)

// claimedEngine names the JS engine the UA implies: every iOS browser is
// WebKit, whatever brand it carries.
func claimedEngine(c uaClaims) string {
	switch {
	case c.isLegacyMS:
		return "chakra"
	case c.os == "ios":
		return "jsc"
	case c.isFirefox:
		return "sm"
	case c.isChromium:
		return "v8"
	case c.isSafari:
		return "jsc"
	}
	return ""
}

// observedEngine classifies the engine from fingerprint.js engine(), or ""
// when the three probes don't agree with each other.
func observedEngine(fp *fingerprint) string {
	if fp.Engine == nil {
		return ""
	}
	msg := fp.Engine.Err
	var eng string
	switch {
	case strings.Contains(msg, "Cannot read prop"):
		eng = "v8"
	case strings.Contains(msg, "is not an object"):
		eng = "jsc"
	case strings.HasSuffix(msg, "is null") || strings.Contains(msg, "has no properties"):
		eng = "sm"
	default:
		return ""
	}
	if fp.Engine.V8Stack != (eng == "v8") || fp.Engine.Moz != (eng == "sm") {
		return ""
	}
	return eng
}

func countIn(have []string, want []string) int {
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	n := 0
	for _, w := range want {
		if set[w] {
			n++
		}
	}
	return n
}

// featureVersionMismatch reports whether the feature matrix contradicts the
// claimed browser version: two or more features missing that shipped well
// before the claim (an older engine behind a newer UA), or two or more
// present that shipped well after it (a newer engine behind an older UA).
func featureVersionMismatch(c uaClaims, feats map[string]bool) bool {
	if len(feats) == 0 {
		return false
	}
	var claimed, margin float64
	var intro func(featureIntro) float64
	switch {
	case c.os == "ios" && c.iosMajor > 0:
		claimed, margin = float64(c.iosMajor)+float64(c.iosMinor)/10, 1
		intro = func(f featureIntro) float64 { return f.safari }
	case c.isFirefox && c.firefoxMajor > 0:
		claimed, margin = float64(c.firefoxMajor), 2
		intro = func(f featureIntro) float64 { return float64(f.firefox) }
	case c.isChromium && c.chromiumMajor > 0:
		claimed, margin = float64(c.chromiumMajor), 2
		intro = func(f featureIntro) float64 { return float64(f.chrome) }
	case c.isSafari && c.safariMajor > 0:
		claimed, margin = float64(c.safariMajor)+float64(c.safariMinor)/10, 1
		intro = func(f featureIntro) float64 { return f.safari }
	default:
		return false
	}
	missing, early := 0, 0
	for id, f := range featureIntros {
		present, sent := feats[id]
		if !sent {
			continue
		}
		v := intro(f)
		if !present && claimed >= v+margin {
			missing++
		}
		if present && v >= claimed+margin+1 {
			early++
		}
	}
	return missing >= 2 || early >= 2
}

var uachOSNames = map[string]string{
	"windows": "Windows", "macos": "macOS", "linux": "Linux",
	"android": "Android", "chromeos": "Chrome OS",
}

func chromiumMajorFromList(list []string) int {
	for _, b := range list {
		if v, ok := strings.CutPrefix(b, "Chromium/"); ok {
			return parseLeadingInt(v)
		}
	}
	return 0
}

func gpuMismatch(c uaClaims, fp *fingerprint) bool {
	renderer := ""
	if fp.WebGL != nil && fp.WebGL.Renderer != nil {
		renderer = *fp.WebGL.Renderer
	}
	apple := c.os == "macos" || c.os == "ios"
	switch {
	case c.os == "":
		return false
	case (strings.Contains(renderer, "Direct3D") || strings.Contains(renderer, "D3D11")) && c.os != "windows":
		return true
	case (strings.Contains(renderer, "Apple M") || strings.Contains(renderer, "Apple GPU")) && !apple:
		return true
	case strings.Contains(renderer, "Metal") && c.os == "windows":
		return true
	case fp.GPU != nil && strings.EqualFold(fp.GPU.Vendor, "apple") && !apple:
		return true
	}
	return false
}

func fontOSMismatch(c uaClaims, fp *fingerprint) bool {
	if fp.Fonts == nil || c.isMobile || c.os == "ios" || c.os == "android" {
		return false
	}
	// Firefox resistFingerprinting (and Tor/Mullvad Browser) restrict fonts
	// to a bundled allowlist and force the UTC zone.
	if c.isFirefox && fp.Intl != nil && (fp.Intl.TimeZone == "UTC" || fp.Intl.TimeZone == "Etc/UTC") {
		return false
	}
	switch c.os {
	case "windows":
		return len(windowsCoreFonts)-countIn(fp.Fonts, windowsCoreFonts) >= 2 ||
			countIn(fp.Fonts, macOnlyFonts) >= 3
	case "macos":
		return len(macCoreFonts)-countIn(fp.Fonts, macCoreFonts) >= 2 ||
			countIn(fp.Fonts, windowsOnlyFonts) >= 3
	}
	return false
}

func voicesOSMismatch(c uaClaims, fp *fingerprint) bool {
	if fp.Voices == nil {
		return false
	}
	if len(fp.Voices) == 0 {
		// Only known-zero (voiceschanged fired with none) reaches here.
		// Windows and macOS always ship local voices.
		return (c.os == "windows" || c.os == "macos") && (c.isChromium || c.isSafari)
	}
	for _, v := range fp.Voices {
		if len(v) < 2 {
			continue
		}
		name, _ := v[0].(string)
		uri, _ := v[1].(string)
		// Online/Google voices are network voices available on any OS.
		windowsLocal := strings.HasPrefix(name, "Microsoft ") && !strings.Contains(name, "Online")
		if (c.os == "macos" || c.os == "ios") && windowsLocal {
			return true
		}
		if c.os == "windows" && strings.HasPrefix(uri, "com.apple.") {
			return true
		}
	}
	return false
}

func navDiffers(a, b *fpNav, compareHC bool) bool {
	if a == nil || b == nil {
		return false
	}
	if a.UA != b.UA || a.Platform != b.Platform {
		return true
	}
	if compareHC && a.HC != nil && b.HC != nil && *a.HC != *b.HC {
		return true
	}
	return false
}

// isBraveClient reports Brave from either the page (navigator.brave) or the
// request's own client hints. Brave Shields farble several values per
// session, so checks that compare those are skipped for it.
func isBraveClient(fp *fingerprint, r *http.Request) bool {
	return (fp.Nav != nil && fp.Nav.Brave) || strings.Contains(r.Header.Get("Sec-CH-UA"), `"Brave"`)
}

// unverifiableReadout reports why a fingerprint cannot be used to verify the
// browser at all, or "" when it can. These are not lies to score but
// readouts that something on the client randomises or blocks (anti-
// fingerprinting settings and extensions), so the client is sent to the
// "can't verify your browser" page rather than a harder challenge.
//
//   - readout_noise: canvas or audio rendered twice in one page differ. A
//     real engine is deterministic within a page.
//   - readout_blocked: canvas readback unavailable, or a solid fill read
//     back transparent or colourless.
//
// Brave Shields and Safari's Advanced Fingerprinting Protection add noise
// by default, with nothing for the visitor to turn off, so readout noise
// is accepted from them. An incomplete fingerprint is left to the scorer
// (fp_incomplete), as it means the page's collector never ran.
func unverifiableReadout(raw interface{}, r *http.Request) string {
	fp, complete := parseFingerprint(raw)
	if !complete {
		return ""
	}
	c := parseUAClaims(r.UserAgent())
	differ := func(pair []*string) bool {
		return len(pair) == 2 && pair[0] != nil && pair[1] != nil && *pair[0] != *pair[1]
	}
	if !isBraveClient(fp, r) && !c.isSafari && c.os != "ios" && (differ(fp.Canvas) || differ(fp.Audio)) {
		return "readout_noise"
	}
	if len(fp.Canvas) == 2 && fp.Canvas[0] == nil && fp.Canvas[1] == nil {
		return "readout_blocked"
	}
	if px := fp.CanvasPx; len(px) == 4 && (px[3] == 0 || (px[0] == px[1] && px[1] == px[2])) {
		return "readout_blocked"
	}
	return ""
}

// reflexFingerprintScore scores fingerprint contradictions. raw is the
// unsealed "fp" signal; r is the request that carried it.
func reflexFingerprintScore(raw interface{}, r *http.Request) (score int, reasons []string) {
	add := func(n int, reason string) {
		score += n
		reasons = append(reasons, reason)
	}

	fp, complete := parseFingerprint(raw)
	if !complete {
		// The page's collector always sends every synchronous section; a
		// client that answered the proof without it reimplemented the page
		// rather than running it. Weighted like a wrong proof answer.
		add(scoreBlock, "fp_incomplete")
		return
	}

	ua := r.UserAgent()
	c := parseUAClaims(ua)
	brave := isBraveClient(fp, r)

	if claimed, observed := claimedEngine(c), observedEngine(fp); claimed != "" && observed != "" && claimed != observed {
		add(5, "engine_mismatch")
	}
	if featureVersionMismatch(c, fp.Features) {
		add(5, "feature_version_mismatch")
	}
	// Brave farbles hardwareConcurrency per realm; compare only UA/platform.
	if navDiffers(fp.Nav, fp.Worker, !brave) {
		add(5, "worker_ua_mismatch")
	}
	if fp.Nav != nil && fp.Nav.UA != "" && fp.Nav.UA != ua {
		add(3, "ua_header_mismatch")
	}

	if fp.UACH != nil {
		mismatch := false
		if want, ok := uachOSNames[c.os]; ok && fp.UACH.Platform != "" && fp.UACH.Platform != want {
			mismatch = true
		}
		if c.os == "android" || c.os == "ios" || c.os == "" {
			// Android tablets omit "Mobile"; only phones are compared.
		} else if fp.UACH.Mobile != c.isMobile {
			mismatch = true
		}
		if m := chromiumMajorFromList(fp.UACH.FullVersionList); m > 0 && c.chromiumMajor > 0 && m != c.chromiumMajor {
			mismatch = true
		}
		if h := strings.Trim(r.Header.Get("Sec-CH-UA-Platform"), `"`); h != "" && fp.UACH.Platform != "" && h != fp.UACH.Platform {
			mismatch = true
		}
		if mismatch {
			add(4, "uach_mismatch")
		}
	}

	if navDiffers(fp.Nav, fp.Iframe, !brave) {
		add(4, "iframe_nav_mismatch")
	}
	if fp.Integrity != nil {
		if len(fp.Integrity.GetterNoThrow) >= 2 {
			add(4, "getter_receiver_tampered")
		}
		if hasForeignNavProp(fp) {
			add(4, "own_prop_on_navigator")
		}
		if !fp.Integrity.ToStringNative {
			add(3, "toString_proxy")
		}
	}
	if gpuMismatch(c, fp) {
		add(4, "gpu_mismatch")
	}
	if fontOSMismatch(c, fp) {
		add(4, "font_os_mismatch")
	}

	if fp.Intl != nil && len(fp.Intl.Languages) > 0 {
		header := cookie.PrimaryLanguage(r.Header.Get("Accept-Language"))
		js := cookie.PrimaryLanguage(fp.Intl.Languages[0])
		if header != "" && js != "" && header != js {
			add(3, "accept_language_mismatch")
		}
	}

	if voicesOSMismatch(c, fp) {
		add(2, "voices_os_mismatch")
	}
	if fp.MQ != nil && fp.Nav != nil {
		coarsePrimary := fp.MQ.PointerCoarse != nil && *fp.MQ.PointerCoarse
		anyCoarse := fp.MQ.AnyCoarse != nil && *fp.MQ.AnyCoarse
		if (coarsePrimary && fp.Nav.MaxTouchPoints == 0) || (c.isMobile && fp.MQ.AnyCoarse != nil && !anyCoarse) {
			add(2, "pointer_touch_mismatch")
		}
	}
	if fp.Devices != nil && !c.isMobile && c.isChromium && c.os != "android" {
		total := 0.0
		for _, n := range fp.Devices {
			total += n
		}
		if total == 0 {
			add(1, "no_media_devices")
		}
	}
	if fp.CDP {
		// Logged, not scored: see fingerprint.js cdp().
		add(0, "cdp_runtime_leak")
	}
	return
}

// fingerprintHashes reduces each surface to a 12-hex component hash for the
// events log and the cluster keys. Raw values are discarded with the
// request. Returns nil when there is no fingerprint.
func fingerprintHashes(raw interface{}) map[string]string {
	fp, _ := parseFingerprint(raw)
	if fp == nil {
		return nil
	}
	h := func(parts ...interface{}) string {
		b, _ := json.Marshal(parts)
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:])[:12]
	}
	out := map[string]string{}
	if len(fp.Canvas) > 0 && fp.Canvas[0] != nil {
		out["canvas"] = h(*fp.Canvas[0])
	}
	if fp.WebGL != nil {
		out["webgl"] = h(fp.WebGL.Vendor, fp.WebGL.Renderer, fp.WebGL.Params, fp.WebGL.Ext, fp.WebGL.Prec)
		if fp.WebGL.Render != nil {
			out["webgl_render"] = h(*fp.WebGL.Render)
		}
	}
	if len(fp.Audio) > 0 && fp.Audio[0] != nil {
		out["audio"] = h(*fp.Audio[0])
	}
	if fp.Fonts != nil {
		f := append([]string{}, fp.Fonts...)
		sort.Strings(f)
		out["fonts"] = h(f)
	}
	if fp.Voices != nil {
		names := make([]string, 0, len(fp.Voices))
		for _, v := range fp.Voices {
			if len(v) > 0 {
				names = append(names, fmt.Sprint(v[0]))
			}
		}
		sort.Strings(names)
		out["voices"] = h(names)
	}
	// Codecs are synchronous and stable; the device list is async and may
	// miss the deadline, so it gets its own hash rather than destabilising
	// this one.
	out["media"] = h(fp.Codecs)
	if fp.Devices != nil {
		out["devices"] = h(fp.Devices)
	}
	if fp.Engine != nil {
		out["engine"] = h(observedEngine(fp), fp.Engine.EvalLen)
	}
	if fp.Features != nil {
		ids := make([]string, 0, len(fp.Features))
		for id, ok := range fp.Features {
			if ok {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		out["features"] = h(ids)
	}
	out["screen"] = h(fp.Screen)
	if fp.Nav != nil {
		out["nav"] = h(fp.Nav.Platform, fp.Nav.HC, fp.Nav.Langs)
	}
	if fp.Intl != nil {
		out["intl"] = h(fp.Intl.Languages, fp.Intl.Locale, fp.Intl.TimeZone)
	}
	return out
}

// privacyNavProps are the own properties of navigator that privacy tools,
// not stealth plugins, define: Brave's navigator.brave, AdGuard's generic
// Tracking Protection stubs (set-constant), Ghostery's GPC, and the
// GPC/DNT/brand properties Privacy Badger and DuckDuckGo set (on the
// prototype today). Spoofed values such as languages or plugins
// (Chameleon) are deliberately absent: stealth plugins patch the same ones.
var privacyNavProps = map[string]bool{
	"brave":                true,
	"getBattery":           true,
	"privateAttribution":   true,
	"globalPrivacyControl": true,
	"doNotTrack":           true,
	"duckduckgo":           true,
}

// hasForeignNavProp reports whether navigator has an own property a real
// browser doesn't define there, privacyNavProps aside.
func hasForeignNavProp(fp *fingerprint) bool {
	if fp.Integrity == nil {
		return false
	}
	for _, p := range fp.Integrity.NavOwnProps {
		if !privacyNavProps[p] {
			return true
		}
	}
	return false
}
