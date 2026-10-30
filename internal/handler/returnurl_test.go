package handler

import "testing"

// A return URL comes from client-supplied input (a query parameter on the
// challenge pages, a form field on the verify endpoints) and ends up in a
// Location header. Anything that can steer that header off-site is an open
// redirect, so the accept list has to be narrow: a site-relative path and
// nothing else.
func TestIsSafeReturnURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		// Legitimate values. Every internal caller passes r.URL.RequestURI(),
		// which always begins with a single slash.
		{"root", "/", true},
		{"simple path", "/dashboard", true},
		{"path with query", "/search?q=hello", true},
		{"path with fragment", "/docs#section", true},
		{"path with encoded slashes stays a path", "/a%2f%2fb", true},

		// Absolute URLs.
		{"https absolute", "https://evil.com", false},
		{"http absolute", "http://evil.com/path", false},
		{"scheme relative host", "//evil.com", false},
		{"opaque scheme", "http:evil.com", false},
		{"javascript scheme", "javascript:alert(1)", false},
		{"data scheme", "data:text/html,<script>alert(1)</script>", false},

		// Browsers fold backslashes to forward slashes in the authority
		// position, so these navigate off-site even though net/url reports
		// them as paths. This is the class the original check missed.
		{"backslash authority", "/\\evil.com", false},
		{"double backslash", "\\\\evil.com", false},
		{"slash backslash", "/\\/evil.com", false},

		// Extra leading slashes collapse to an authority in some browsers.
		{"triple slash", "///evil.com", false},
		{"quadruple slash", "////evil.com", false},

		// Not site-relative: would resolve against the current directory,
		// and no legitimate caller produces it.
		{"empty", "", false},
		{"bare host", "evil.com", false},
		{"relative path", "foo/bar", false},
		{"parent traversal", "../evil", false},

		// Control characters are stripped or ignored by some browsers, which
		// can resurrect an authority after the fact.
		{"raw tab", "/\t/evil.com", false},
		{"raw newline", "/\n//evil.com", false},
		{"raw CR", "/\r//evil.com", false},
	}

	for _, c := range cases {
		if got := isSafeReturnURL(c.in); got != c.want {
			t.Errorf("%s: isSafeReturnURL(%q) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

// safeReturnURL is what the handlers actually call: it must never return a
// value that isSafeReturnURL would reject, so a caller cannot forget the
// fallback and emit attacker-controlled input into a Location header.
func TestSafeReturnURLAlwaysReturnsSomethingSafe(t *testing.T) {
	inputs := []string{
		"", "/", "/ok", "https://evil.com", "//evil.com", "/\\evil.com",
		"///evil.com", "evil.com", "javascript:alert(1)", "/\t/evil.com",
	}
	for _, in := range inputs {
		got := safeReturnURL(in)
		if !isSafeReturnURL(got) {
			t.Errorf("safeReturnURL(%q) = %q, which isSafeReturnURL rejects", in, got)
		}
	}
}

func TestSafeReturnURLPreservesSafeInputAndFallsBackOtherwise(t *testing.T) {
	if got := safeReturnURL("/dashboard?a=b"); got != "/dashboard?a=b" {
		t.Errorf("a safe path must be preserved verbatim, got %q", got)
	}
	if got := safeReturnURL("https://evil.com"); got != "/" {
		t.Errorf("an unsafe value must fall back to \"/\", got %q", got)
	}
}
