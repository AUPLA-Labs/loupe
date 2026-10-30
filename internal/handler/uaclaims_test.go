package handler

import "testing"

func TestParseUAClaims(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want uaClaims
	}{
		{
			"chrome desktop",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.91 Safari/537.36",
			uaClaims{hasMozilla: true, isChromium: true, chromiumMajor: 124, chromiumMinor: 0, os: "linux"},
		},
		{
			"edge is chromium, not safari",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
			uaClaims{hasMozilla: true, isChromium: true, chromiumMajor: 124, chromiumMinor: 0, os: "windows"},
		},
		{
			"firefox desktop",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
			uaClaims{hasMozilla: true, isFirefox: true, firefoxMajor: 133, firefoxMinor: 0, os: "windows"},
		},
		{
			"ios safari 18",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
			uaClaims{hasMozilla: true, isSafari: true, safariMajor: 18, safariMinor: 0, isIOS: true, iosMajor: 18, isMobile: true, os: "ios"},
		},
		{
			"ios safari 14 (pre-16.4)",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
			uaClaims{hasMozilla: true, isSafari: true, safariMajor: 14, safariMinor: 0, isIOS: true, iosMajor: 14, isMobile: true, os: "ios"},
		},
		{
			"chrome on ios is webkit at the ios version",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/122.0.6261.89 Mobile/15E148 Safari/604.1",
			uaClaims{hasMozilla: true, isSafari: true, isIOS: true, iosMajor: 17, iosMinor: 4, isMobile: true, os: "ios"},
		},
		{
			"android chrome is android, not linux",
			"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
			uaClaims{hasMozilla: true, isChromium: true, chromiumMajor: 131, isMobile: true, os: "android"},
		},
		{
			"lynx text browser",
			"Lynx/2.9.0dev.6 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/1.1.1f",
			uaClaims{},
		},
		{
			"chrome version has no dot: minor must not bleed from a later token",
			"Mozilla/5.0 Chrome/124 Safari/537.36",
			uaClaims{hasMozilla: true, isChromium: true, chromiumMajor: 124, chromiumMinor: 0},
		},
	}
	for _, c := range cases {
		if got := parseUAClaims(c.ua); got != c.want {
			t.Errorf("%s: parseUAClaims(%q) = %+v, want %+v", c.name, c.ua, got, c.want)
		}
	}
}

func TestUAMajorMinorVersionDoesNotBleedAcrossTokens(t *testing.T) {
	// Regression test: when the matched token's own version has no dot
	// (e.g. a malformed/spoofed UA), the minor version must stay 0 rather
	// than being fabricated from a later, unrelated token's digits.
	ua := "Mozilla/5.0 Chrome/124 Safari/537.36"
	major, minor := uaMajorMinorVersion(ua, "Chrome/")
	if major != 124 || minor != 0 {
		t.Errorf("uaMajorMinorVersion(%q, %q) = (%d, %d), want (124, 0)", ua, "Chrome/", major, minor)
	}
}

func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		name                               string
		major, minor, wantMajor, wantMinor int
		want                               bool
	}{
		{"higher major", 124, 0, 76, 0, true},
		{"lower major", 60, 0, 76, 0, false},
		{"safari at exact boundary", 16, 4, 16, 4, true},
		{"safari just under boundary", 16, 3, 16, 4, false},
		{"safari a major version ahead", 17, 0, 16, 4, true},
		{"unparsed major is never at least anything", 0, 0, 1, 0, false},
	}
	for _, c := range cases {
		if got := versionAtLeast(c.major, c.minor, c.wantMajor, c.wantMinor); got != c.want {
			t.Errorf("%s: versionAtLeast(%d,%d,%d,%d) = %v, want %v",
				c.name, c.major, c.minor, c.wantMajor, c.wantMinor, got, c.want)
		}
	}
}
