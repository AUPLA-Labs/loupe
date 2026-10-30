package handler

import (
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/rules"
)

func TestCanonicalPath(t *testing.T) {
	for _, tc := range []struct {
		target    string
		clean     string
		anomalies []string
	}{
		{"/", "/", nil},
		{"/a/b/", "/a/b/", nil},
		{"/.well-known/x", "/.well-known/x", nil},
		{"/a/x.php", "/a/x.php", nil},
		{"//admin", "/admin", nil},
		{"/a//b/", "/a/b/", nil},
		{"/a/../admin", "/admin", []string{"dot_segment"}},
		{"/./admin", "/admin", []string{"dot_segment"}},
		{"/admin/%2e%2e/admin", "/admin", []string{"dot_segment"}},
		{"/%2561dmin", "/admin", []string{"double_encoded"}},
		{"/a/%252e%252e/admin", "/admin", []string{"double_encoded", "dot_segment"}},
		{"/admin%5c..%5csecret", "/secret", []string{"backslash", "dot_segment"}},
		{"/admin%00.php", "/admin\x00.php", []string{"null_byte"}},
		{"/%c0%afadmin", "/\xc0\xafadmin", []string{"overlong_utf8"}},
		{"/%ff", "/\xff", []string{"invalid_utf8"}},
		{"/caf%C3%A9", "/café", nil},
		{"/..", "/", []string{"dot_segment"}},
	} {
		r := httptest.NewRequest("GET", tc.target, nil)
		clean, anomalies := canonicalPath(r)
		if clean != tc.clean || !slices.Equal(anomalies, tc.anomalies) {
			t.Errorf("%s: got %q %v, want %q %v", tc.target, clean, anomalies, tc.clean, tc.anomalies)
		}
		for _, a := range anomalies {
			if !slices.Contains(rules.PathAnomalies, a) {
				t.Errorf("%s: anomaly %q is not in rules.PathAnomalies, so no rule can match it", tc.target, a)
			}
		}
	}
}

func TestCanonicalPathPlainAllocatesNothing(t *testing.T) {
	r := httptest.NewRequest("GET", "/blog/2026/10/hello-world", nil)
	if n := testing.AllocsPerRun(100, func() { canonicalPath(r) }); n != 0 {
		t.Errorf("%v allocations for a plain path, want 0", n)
	}
}

func TestPathAnomaliesAddToRequestScore(t *testing.T) {
	r := chromeNav()
	r.URL.Path = "/a/../b\x00" // URL.Path is the decoded form
	plain := chromeNav()
	base, _ := reflexRequestScore(plain, nil)
	score, reasons := reflexRequestScore(r, nil)
	if score-base != 6 || !slices.Contains(reasons, "path_null_byte") || !slices.Contains(reasons, "path_dot_segment") {
		t.Errorf("score %d (base %d) reasons %v, want +6 from two anomalies", score, base, reasons)
	}
	r.URL.Path = "/%25/../x\\y\x00"
	score, _ = reflexRequestScore(r, nil)
	if score-base != 6 {
		t.Errorf("four anomalies scored +%d, want the +6 cap", score-base)
	}
}
