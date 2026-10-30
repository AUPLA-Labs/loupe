package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
)

// setupServer is a console whose users file doesn't exist yet.
func setupServer(t *testing.T, dir string) (*Server, http.Handler) {
	t.Helper()
	s := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), filepath.Join(dir, "config.yaml"), AuthOptions{
		File:           filepath.Join(dir, "admin_auth.yaml"),
		SetupTokenFile: filepath.Join(dir, "setup_token"),
	})
	s.listen = "127.0.0.1:9090"
	return s, s.Handler()
}

// setupPath is the path of the server's one setup URL.
func setupPath(t *testing.T, s *Server) string {
	t.Helper()
	urls := s.SetupURLs()
	if len(urls) == 0 {
		t.Fatal("no setup URL")
	}
	u, err := url.Parse(urls[0])
	if err != nil {
		t.Fatal(err)
	}
	return u.Path
}

func postSetup(h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://console.lan"+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://console.lan")
	r.RemoteAddr = "192.0.2.7:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func setupForm(user string) url.Values {
	return url.Values{"username": {user}, "password": {"correct horse"}, "confirm": {"correct horse"}}
}

func TestSetupOnlyWhenNoUsersFile(t *testing.T) {
	dir := t.TempDir()
	s, h := setupServer(t, dir)
	p := setupPath(t, s)
	if w := get(h, p, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Create the first admin") {
		t.Fatalf("GET setup = %d, want the setup form", w.Code)
	}
	if w := get(h, "/login", nil); !strings.Contains(w.Body.String(), "No admin yet") {
		t.Errorf("login page in setup mode doesn't say there is no admin yet")
	}

	// A valid users file: no setup.
	dir2 := t.TempDir()
	if err := config.SaveAdminAuth(filepath.Join(dir2, "admin_auth.yaml"), &config.AdminAuth{Users: []config.AdminUser{{Username: "pat", PasswordHash: testHash(t, "correct horse"), Role: config.RoleAdmin}}}); err != nil {
		t.Fatal(err)
	}
	s2, h2 := setupServer(t, dir2)
	if got := s2.SetupURLs(); len(got) != 0 {
		t.Errorf("with users, SetupURLs = %v", got)
	}
	if w := get(h2, p, nil); w.Code != http.StatusNotFound {
		t.Errorf("GET setup with users = %d, want 404", w.Code)
	}

	// A broken users file: no setup, and still locked.
	dir3 := t.TempDir()
	os.WriteFile(filepath.Join(dir3, "admin_auth.yaml"), []byte("users: [\n"), 0o600)
	s3, h3 := setupServer(t, dir3)
	if got := s3.SetupURLs(); len(got) != 0 {
		t.Errorf("with a broken file, SetupURLs = %v", got)
	}
	if w := get(h3, p, nil); w.Code != http.StatusNotFound {
		t.Errorf("GET setup with a broken file = %d, want 404", w.Code)
	}
	if w := postLogin(h3, url.Values{"username": {"pat"}, "password": {"correct horse"}}, nil); w.Code != http.StatusServiceUnavailable {
		t.Errorf("login with a broken file = %d, want 503", w.Code)
	}
}

func TestSetupCreatesAdmin(t *testing.T) {
	dir := t.TempDir()
	s, h := setupServer(t, dir)
	p := setupPath(t, s)
	w := postSetup(h, p, setupForm("pat"))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("POST setup = %d %q %s, want 303 to /login", w.Code, w.Header().Get("Location"), w.Body)
	}
	a, err := config.LoadAdminAuth(filepath.Join(dir, "admin_auth.yaml"))
	if err != nil || len(a.Users) != 1 || a.Users[0].Username != "pat" || a.Users[0].Role != config.RoleAdmin {
		t.Fatalf("users file = %+v (%v), want one admin pat", a, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "setup_token")); !os.IsNotExist(err) {
		t.Errorf("token file still there: %v", err)
	}
	if w := get(h, p, nil); w.Code != http.StatusNotFound {
		t.Errorf("GET setup after use = %d, want 404", w.Code)
	}
	if got := s.SetupURLs(); len(got) != 0 {
		t.Errorf("SetupURLs after use = %v", got)
	}
	if w := postLogin(h, url.Values{"username": {"pat"}, "password": {"correct horse"}}, nil); w.Code != http.StatusSeeOther {
		t.Errorf("sign-in as the new admin = %d %s", w.Code, w.Body)
	}
}

func TestSetupRejectsBadForm(t *testing.T) {
	dir := t.TempDir()
	s, h := setupServer(t, dir)
	p := setupPath(t, s)
	for name, f := range map[string]url.Values{
		"mismatch": {"username": {"pat"}, "password": {"correct horse"}, "confirm": {"correct horsf"}},
		"short":    {"username": {"pat"}, "password": {"short"}, "confirm": {"short"}},
		"bad name": setupForm("no spaces allowed"),
		"no name":  setupForm(""),
	} {
		if w := postSetup(h, p, f); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, w.Code)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "admin_auth.yaml")); !os.IsNotExist(err) {
		t.Error("a rejected form wrote the users file")
	}
	r := httptest.NewRequest("POST", "http://console.lan"+p, strings.NewReader(setupForm("pat").Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-site POST = %d, want 403", w.Code)
	}
}

func TestSetupConcurrentSubmitsOneAdmin(t *testing.T) {
	dir := t.TempDir()
	s, h := setupServer(t, dir)
	p := setupPath(t, s)
	var wg sync.WaitGroup
	codes := make([]int, 10)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = postSetup(h, p, setupForm("admin"+string(rune('a'+i)))).Code
		}()
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == http.StatusSeeOther {
			ok++
		}
	}
	a, err := config.LoadAdminAuth(filepath.Join(dir, "admin_auth.yaml"))
	if ok != 1 || err != nil || len(a.Users) != 1 {
		t.Fatalf("%d succeeded, file %+v (%v); want exactly one admin", ok, a, err)
	}
}

func TestSetupWrongToken(t *testing.T) {
	_, h := setupServer(t, t.TempDir())
	var last int
	for range 6 {
		last = get(h, "/setup/0000", nil).Code
	}
	if w := get(h, "/setup/0000", nil); w.Code != http.StatusNotFound && w.Code != http.StatusTooManyRequests {
		t.Errorf("wrong token = %d", w.Code)
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("after 6 wrong tokens = %d, want 429", last)
	}
}

func TestSetupTokenSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	a, _ := setupServer(t, dir)
	b, _ := setupServer(t, dir)
	if setupPath(t, a) != setupPath(t, b) {
		t.Error("a restart changed the setup link")
	}
	st, err := os.Stat(filepath.Join(dir, "setup_token"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("token file %v (%v), want mode 0600", st, err)
	}
}
