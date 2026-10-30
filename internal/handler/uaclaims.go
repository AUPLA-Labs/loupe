package handler

import "strings"

// uaClaims summarizes what a User-Agent string asserts about the browser,
// parsed from the string itself. Every field is a claim, not a verified
// fact: version-sensitive checks elsewhere gate on these claims so that a
// genuinely old browser, a text browser, or a niche client scores zero
// rather than being judged against a capability it never claimed to have.
// If the claim cannot be parsed, the corresponding Major/Minor stay 0 and
// versionAtLeast reports false for them — never true.
type uaClaims struct {
	hasMozilla bool // UA starts with "Mozilla/"

	isChromium                   bool // UA contains "Chrome/" — also true for Chromium-based Edge, Opera, Brave
	chromiumMajor, chromiumMinor int

	isFirefox                  bool
	firefoxMajor, firefoxMinor int

	isSafari                 bool // UA contains "Safari/" and does NOT also contain "Chrome/"
	safariMajor, safariMinor int

	// isLegacyMS is Internet Explorer (Trident) or pre-Chromium Edge
	// (EdgeHTML, "Edge/"; Chromium Edge says "Edg/"). Neither engine runs
	// the challenge scripts, so any client claiming one that does is lying.
	isLegacyMS bool

	isIOS              bool // UA contains "iPhone" or "iPad"
	iosMajor, iosMinor int  // from "OS 17_4 like Mac OS X"; every iOS browser is WebKit at this version
	isMobile           bool // UA contains the "Mobile" token — covers iOS and most Android phones

	os string // "windows", "macos", "linux", "android", "chromeos", "ios", or "" if unclear
}

func parseUAClaims(ua string) uaClaims {
	var c uaClaims
	c.hasMozilla = strings.HasPrefix(ua, "Mozilla/")

	c.isChromium = strings.Contains(ua, "Chrome/")
	if c.isChromium {
		c.chromiumMajor, c.chromiumMinor = uaMajorMinorVersion(ua, "Chrome/")
	}

	c.isFirefox = strings.Contains(ua, "Firefox/")
	if c.isFirefox {
		c.firefoxMajor, c.firefoxMinor = uaMajorMinorVersion(ua, "Firefox/")
	}

	c.isSafari = strings.Contains(ua, "Safari/") && !c.isChromium
	if c.isSafari {
		c.safariMajor, c.safariMinor = uaMajorMinorVersion(ua, "Version/")
	}

	c.isLegacyMS = strings.Contains(ua, "Trident/") || strings.Contains(ua, "MSIE ") || strings.Contains(ua, " Edge/")

	c.isIOS = strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad")
	if c.isIOS {
		c.iosMajor, c.iosMinor = iosVersion(ua)
	}
	c.isMobile = strings.Contains(ua, "Mobile")
	c.os = uaOS(ua, c.isIOS)
	return c
}

// uaOS names the operating system the UA claims. Order matters: Android
// UAs also say "Linux", and iPadOS desktop-mode UAs say "Macintosh".
func uaOS(ua string, isIOS bool) string {
	switch {
	case isIOS || strings.Contains(ua, "iPod"):
		return "ios"
	case strings.Contains(ua, "Android"):
		return "android"
	case strings.Contains(ua, "CrOS"):
		return "chromeos"
	case strings.Contains(ua, "Windows"):
		return "windows"
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X"):
		return "macos"
	case strings.Contains(ua, "Linux"):
		return "linux"
	}
	return ""
}

// iosVersion parses "OS 17_4" from "CPU iPhone OS 17_4 like Mac OS X" (or
// "CPU OS 17_4 like" on iPad).
func iosVersion(ua string) (major, minor int) {
	idx := strings.Index(ua, " OS ")
	if idx < 0 {
		return 0, 0
	}
	rest := strings.ReplaceAll(ua[idx+len(" OS "):], "_", ".")
	return uaMajorMinorVersion("v/"+rest, "v/")
}

// uaMajorMinorVersion parses the major and minor integers following token in
// ua, e.g. uaMajorMinorVersion("...Chrome/124.0.6367.91...", "Chrome/")
// returns (124, 0). Returns (0, 0) if token is absent or not followed by a
// parseable integer.
func uaMajorMinorVersion(ua, token string) (major, minor int) {
	idx := strings.Index(ua, token)
	if idx < 0 {
		return 0, 0
	}
	rest := ua[idx+len(token):]
	end := 0
	for end < len(rest) && (rest[end] == '.' || (rest[end] >= '0' && rest[end] <= '9')) {
		end++
	}
	version := rest[:end]
	parts := strings.SplitN(version, ".", 3)
	major = parseLeadingInt(parts[0])
	if major == 0 {
		return 0, 0
	}
	if len(parts) > 1 {
		minor = parseLeadingInt(parts[1])
	}
	return major, minor
}

func parseLeadingInt(s string) int {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n := 0
	for _, ch := range s[:end] {
		n = n*10 + int(ch-'0')
	}
	return n
}

// versionAtLeast reports whether major.minor is at least wantMajor.wantMinor.
// major == 0 means the claim was absent or unparseable, and always reports
// false — an unparseable claim gates a check off, never on.
func versionAtLeast(major, minor, wantMajor, wantMinor int) bool {
	if major == 0 {
		return false
	}
	if major != wantMajor {
		return major > wantMajor
	}
	return minor >= wantMinor
}
