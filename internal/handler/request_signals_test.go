package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/tier"
)

func newDocRequest(ua string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	return r
}

const chrome131UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.140 Safari/537.36"
const chrome60UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.101 Safari/537.36"
const iosSafari14UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
const lynxUA = "Lynx/2.9.0dev.6 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/1.1.1f"

func TestReflexRequestScore_CleanChromeIsZero(t *testing.T) {
	r := newDocRequest(chrome131UA)
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.Header.Set("Sec-Fetch-Site", "none")
	r.Header.Set("Sec-CH-UA", `"Chromium";v="131", "Not_A Brand";v="24"`)
	score, reasons := reflexRequestScore(r, nil)
	if score != 0 {
		t.Errorf("clean Chrome 131: score = %d, reasons = %v, want 0", score, reasons)
	}
}

func TestReflexRequestScore_MissingSecFetch(t *testing.T) {
	r := newDocRequest(chrome131UA)
	r.Header.Set("Sec-CH-UA", `"Chromium";v="131"`)
	score, reasons := reflexRequestScore(r, nil)
	if !containsReason(reasons, "sec_fetch_missing") {
		t.Errorf("expected sec_fetch_missing, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexRequestScore_MissingSecCHUA(t *testing.T) {
	r := newDocRequest(chrome131UA)
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.Header.Set("Sec-Fetch-Site", "none")
	score, reasons := reflexRequestScore(r, nil)
	if !containsReason(reasons, "sec_ch_ua_missing") {
		t.Errorf("expected sec_ch_ua_missing, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexRequestScore_MalformedChromeVersion(t *testing.T) {
	r := newDocRequest("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	score, reasons := reflexRequestScore(r, nil)
	if !containsReason(reasons, "ua_malformed_chrome") {
		t.Errorf("expected ua_malformed_chrome, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexRequestScore_Chrome60ScoresZeroOnSecChecks(t *testing.T) {
	// Guard test: Chrome 60 predates Sec-Fetch-* (76) and Sec-CH-UA (89).
	// Neither header is present, and neither must be scored.
	r := newDocRequest(chrome60UA)
	score, reasons := reflexRequestScore(r, nil)
	if score != 0 {
		t.Errorf("Chrome 60 with no Sec-* headers: score = %d, reasons = %v, want 0", score, reasons)
	}
}

func TestReflexRequestScore_IOSSafari14ScoresZero(t *testing.T) {
	// Guard test: Safari's Sec-Fetch-* support starts at 16.4; 14 must not
	// be judged against it, and Safari never sends Sec-CH-UA at all.
	r := newDocRequest(iosSafari14UA)
	score, reasons := reflexRequestScore(r, nil)
	if score != 0 {
		t.Errorf("iOS Safari 14: score = %d, reasons = %v, want 0", score, reasons)
	}
}

func TestReflexRequestScore_LynxIsNotBrowserShaped(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", lynxUA)
	score, reasons := reflexRequestScore(r, nil)
	if score != 3 || !containsReason(reasons, "ua_not_browser_shaped") {
		t.Errorf("lynx: score = %d, reasons = %v, want 3 [ua_not_browser_shaped]", score, reasons)
	}
}

func TestReflexRequestScore_NoAcceptLanguage(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", chrome131UA)
	r.Header.Set("Accept", "text/html")
	// Accept-Language deliberately not set.
	score, reasons := reflexRequestScore(r, nil)
	if !containsReason(reasons, "no_accept_language") {
		t.Errorf("expected no_accept_language, got score=%d reasons=%v", score, reasons)
	}
}

func TestReflexRequestScore_ExploitPath(t *testing.T) {
	r := newDocRequest(chrome131UA)
	r.URL.Path = "/wp-admin/install.php"
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.Header.Set("Sec-Fetch-Site", "none")
	r.Header.Set("Sec-CH-UA", `"Chromium";v="131"`)
	score, reasons := reflexRequestScore(r, []string{"/wp-admin/", "/.env"})
	if !containsReason(reasons, "exploit_path") || score < 4 {
		t.Errorf("expected exploit_path, got score=%d reasons=%v", score, reasons)
	}
}

func TestRequestScoreTier(t *testing.T) {
	cfg := config.RequestScoreConfig{Tier2: 2, Tier3: 4, Tier4: 8}
	cases := []struct {
		score int
		want  tier.Tier
	}{
		{0, tier.Pulse},
		{1, tier.Pulse},
		{2, tier.LumenAuto},
		{3, tier.LumenAuto},
		{4, tier.SingleClick},
		{7, tier.SingleClick},
		{8, tier.Prism},
		{20, tier.Prism},
	}
	for _, c := range cases {
		if got := requestScoreTier(c.score, cfg); got != c.want {
			t.Errorf("requestScoreTier(%d) = %v, want %v", c.score, got, c.want)
		}
	}
}
