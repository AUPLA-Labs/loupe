package handler

import (
	"net/url"
	"strings"
)

// isSafeReturnURL reports whether s is a site-relative path that can be placed
// in a Location header without steering the client off-site.
//
// The accept list is deliberately narrow: exactly one leading slash, and a
// second character that cannot turn the value into an authority. Asking
// net/url for an empty Scheme and Host is not sufficient on its own —
// browsers fold "\" to "/" in the authority position, so "/\evil.com" parses
// as an innocent path but navigates to https://evil.com, and extra leading
// slashes ("///evil.com") collapse the same way. Control characters are
// rejected because some browsers strip them before resolving, which can
// resurrect an authority after the check has passed.
func isSafeReturnURL(s string) bool {
	if s == "" || s[0] != '/' {
		return false
	}
	if len(s) > 1 && (s[1] == '/' || s[1] == '\\') {
		return false
	}
	if strings.ContainsAny(s, "\\\x00\t\r\n") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "" && u.Host == ""
}

// safeReturnURL returns s when it is a safe site-relative path and "/"
// otherwise. Handlers call this rather than isSafeReturnURL directly, so that
// omitting the fallback is not something a caller can forget to do: every
// return URL reaching a Location header has passed through here.
func safeReturnURL(s string) string {
	if isSafeReturnURL(s) {
		return s
	}
	return "/"
}
