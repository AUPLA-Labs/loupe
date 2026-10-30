// internal/handler/publicpath_test.go
package handler

import "testing"

func TestIsPublicPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/favicon.ico", true},
		{"/favicon.png", true},
		{"/favicon.svg", true},
		{"/apple-touch-icon.png", true},
		{"/apple-touch-icon-precomposed.png", true},
		{"/robots.txt", true},
		{"/sitemap.xml", true},
		{"/ads.txt", true},
		{"/security.txt", true},
		{"/.well-known/security.txt", true},
		{"/.well-known/change-password", true},
		{"/", false},
		{"/index.html", false},
		{"/robots.txt/../secret", false},
		{"/wellrobots.txt", false},
		{"/.well-known/../secret", false},
	}
	for _, c := range cases {
		if got := isPublicPath(c.path); got != c.want {
			t.Errorf("isPublicPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
