package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/bots"
)

func robotsHandler(t *testing.T, mode bots.RobotsMode, backend http.HandlerFunc) *Handler {
	t.Helper()
	srv := httptest.NewServer(backend)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	m, err := bots.New(bots.Options{PolicyFile: filepath.Join(t.TempDir(), "bots.yaml"), RangesDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	p := m.Policy()
	p.Robots.Mode = mode
	if _, err := m.Save(p); err != nil {
		t.Fatal(err)
	}
	return &Handler{bots: m, robots: newRobotsCache(u)}
}

func getRobots(h *Handler, host string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/robots.txt", nil)
	r.Host = host
	w := httptest.NewRecorder()
	if !h.serveRobots(w, r) {
		w.Code = -1 // not handled: would be proxied
	}
	return w
}

func TestManagedRobotsMerge(t *testing.T) {
	var gotHost string
	h := robotsHandler(t, bots.RobotsMerge, func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		if r.Host == "none.example" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("User-agent: *\nDisallow: /private\n"))
	})
	w := getRobots(h, "site.example")
	body := w.Body.String()
	if w.Code != 200 || gotHost != "site.example" {
		t.Fatalf("code %d, backend saw host %q", w.Code, gotHost)
	}
	if !strings.Contains(body, "User-agent: Bytespider") || !strings.HasSuffix(body, "Disallow: /private\n") {
		t.Fatalf("merged body:\n%s", body)
	}
	if strings.Index(body, "Bytespider") > strings.Index(body, "/private") {
		t.Fatal("managed section must come first")
	}
	if w := getRobots(h, "none.example"); w.Code != 200 || strings.Contains(w.Body.String(), "/private") {
		t.Fatalf("site without robots.txt: %d\n%s", w.Code, w.Body.String())
	}
}

func TestManagedRobotsOriginDown(t *testing.T) {
	h := robotsHandler(t, bots.RobotsMerge, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	})
	if w := getRobots(h, "site.example"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("origin 5xx with no cached copy: got %d, want 503", w.Code)
	}
}

func TestManagedRobotsOffAndReplace(t *testing.T) {
	called := false
	backend := func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte("User-agent: *\nDisallow: /x\n"))
	}
	if w := getRobots(robotsHandler(t, bots.RobotsOff, backend), "a.example"); w.Code != -1 {
		t.Fatal("mode off must pass /robots.txt through to the site")
	}
	w := getRobots(robotsHandler(t, bots.RobotsReplace, backend), "a.example")
	if w.Code != 200 || called || strings.Contains(w.Body.String(), "/x") || !strings.Contains(w.Body.String(), "Allow: /") {
		t.Fatalf("replace: code %d, backend called %v\n%s", w.Code, called, w.Body.String())
	}
}
