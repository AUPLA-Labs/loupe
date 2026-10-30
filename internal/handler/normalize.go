package handler

import (
	"net/http"
	"net/url"
	"path"
	"strings"
	"unicode/utf8"
)

// Path anomalies (rules.PathAnomalies lists the same names): encodings a browser following a link never produces, but
// which are used to slip past filters that compare paths as written.
const (
	anomalyDoubleEncoded = "double_encoded" // %25xx: decodes to another escape
	anomalyNullByte      = "null_byte"
	anomalyBackslash     = "backslash"
	anomalyDotSegment    = "dot_segment" // a /./ or /../ segment, literal or encoded
	anomalyInvalidUTF8   = "invalid_utf8"
	anomalyOverlongUTF8  = "overlong_utf8" // a character encoded in more bytes than needed, e.g. %c0%af for /
)

// canonicalPath is the request's path as the backend most likely resolves
// it, which is what rules match: decoded (twice when it was double-encoded),
// backslashes read as slashes, dot segments and repeated slashes resolved.
// A trailing slash is kept. anomalies names what had to be undone.
//
// The common path (plain ASCII, nothing to resolve) costs a scan and
// allocates nothing.
func canonicalPath(r *http.Request) (clean string, anomalies []string) {
	p := r.URL.Path // already decoded once by net/http
	if plainPath(p) {
		return p, nil
	}
	if hasEscape(p) {
		anomalies = append(anomalies, anomalyDoubleEncoded)
		if d, err := url.PathUnescape(p); err == nil {
			p = d
		}
	}
	if strings.IndexByte(p, 0) >= 0 {
		anomalies = append(anomalies, anomalyNullByte)
	}
	if strings.IndexByte(p, '\\') >= 0 {
		anomalies = append(anomalies, anomalyBackslash)
		p = strings.ReplaceAll(p, `\`, "/")
	}
	if !utf8.ValidString(p) {
		if hasOverlong(p) {
			anomalies = append(anomalies, anomalyOverlongUTF8)
		} else {
			anomalies = append(anomalies, anomalyInvalidUTF8)
		}
	}
	if hasDotSegment(p) {
		anomalies = append(anomalies, anomalyDotSegment)
	}
	trailing := strings.HasSuffix(p, "/")
	clean = path.Clean("/" + p)
	if trailing && clean != "/" {
		clean += "/"
	}
	return clean, anomalies
}

// plainPath reports whether p needs no work: ASCII, no escapes, no
// backslash or NUL, no empty or dot segments.
func plainPath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c >= 0x80, c == '%', c == '\\', c == 0:
			return false
		case c == '/' && i+1 < len(p) && (p[i+1] == '/' || p[i+1] == '.'):
			return false
		}
	}
	return true
}

// hasEscape reports whether p, already decoded once, still holds a valid
// percent escape.
func hasEscape(p string) bool {
	for i := 0; i+2 < len(p); i++ {
		if p[i] == '%' && isHex(p[i+1]) && isHex(p[i+2]) {
			return true
		}
	}
	return false
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// hasOverlong reports an overlong UTF-8 sequence: a lead byte that can only
// start one (C0, C1), or E0/F0 followed by a byte that makes it one.
func hasOverlong(p string) bool {
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == 0xC0 || c == 0xC1:
			return true
		case c == 0xE0 && i+1 < len(p) && p[i+1] >= 0x80 && p[i+1] < 0xA0:
			return true
		case c == 0xF0 && i+1 < len(p) && p[i+1] >= 0x80 && p[i+1] < 0x90:
			return true
		}
	}
	return false
}
