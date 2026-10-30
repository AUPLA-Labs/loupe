package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/bots"
)

// The backend is told the scheme the visitor used, not always https:
// behind a plain-HTTP front proxy it would otherwise build https:// links
// and redirects that point nowhere.
func TestProxyForwardsVisitorScheme(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Forwarded-Proto")
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	proxy := (&Handler{}).buildProxy(u)

	cases := []struct {
		name, target, proto, want string
	}{
		{"plain HTTP, no proxy header", "http://example.com/", "", "http"},
		{"direct TLS", "https://example.com/", "", "https"},
		{"front proxy says https", "http://example.com/", "https", "https"},
		{"front proxy says http", "http://example.com/", "http", "http"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.target, nil)
			if tc.proto != "" {
				r.Header.Set("X-Forwarded-Proto", tc.proto)
			}
			proxy.ServeHTTP(httptest.NewRecorder(), r)
			if got != tc.want {
				t.Errorf("backend saw X-Forwarded-Proto %q, want %q", got, tc.want)
			}
		})
	}
}

// The site's robots.txt is fetched with the scheme of the request that
// asked for it, and each scheme is cached on its own.
func TestRobotsFetchUsesVisitorScheme(t *testing.T) {
	var seen []string
	h := robotsHandler(t, bots.RobotsMerge, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("X-Forwarded-Proto"))
		w.Write([]byte("User-agent: *\nDisallow: /" + r.Header.Get("X-Forwarded-Proto") + "\n")) //nolint:errcheck
	})
	for _, proto := range []string{"http", "https"} {
		r := httptest.NewRequest("GET", "/robots.txt", nil)
		r.Host = "example.com"
		r.Header.Set("X-Forwarded-Proto", proto)
		w := httptest.NewRecorder()
		if !h.serveRobots(w, r) {
			t.Fatal("robots.txt not served")
		}
	}
	if len(seen) != 2 || seen[0] != "http" || seen[1] != "https" {
		t.Errorf("backend fetches saw %q, want [http https]", seen)
	}
}
