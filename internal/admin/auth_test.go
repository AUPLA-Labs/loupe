package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
	"golang.org/x/crypto/bcrypt"
)

func testHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

// testOpts is the options for one admin user, or for no auth at all when the
// hash is empty.
func testOpts(username, hash, sessions string) AuthOptions {
	o := AuthOptions{SessionsPath: sessions}
	if hash != "" {
		o.Users = []config.AdminUser{{Username: username, PasswordHash: hash, Role: config.RoleAdmin}}
	}
	return o
}

func authedHandler(t *testing.T, hash, sessions string) http.Handler {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	return NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), cfg, testOpts("admin", hash, sessions)).Handler()
}

func postLogin(h http.Handler, form url.Values, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://console.lan/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "192.0.2.7:5555"
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func sessionFrom(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie set (status %d)", w.Code)
	return nil
}

func get(h http.Handler, path string, c *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://console.lan"+path, nil)
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestLoginGatesDashboardAndAPI(t *testing.T) {
	h := authedHandler(t, testHash(t, "correct horse"), "")

	if w := get(h, "/", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("GET / without session = %d %q, want redirect to /login", w.Code, w.Header().Get("Location"))
	}
	if w := get(h, "/api/health", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("API without session = %d, want 401", w.Code)
	}
	if w := get(h, "/api/health", &http.Cookie{Name: sessionCookie, Value: "forged"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("API with forged session = %d, want 401", w.Code)
	}
	for _, p := range []string{"/login", "/icons/favicon.ico", "/fonts/monasans.woff2", "/fonts/hubotsans.woff2"} {
		if w := get(h, p, nil); w.Code != http.StatusOK {
			t.Fatalf("public %s = %d, want 200", p, w.Code)
		}
	}
	if w := get(h, "/login", nil); w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("login page is missing security headers")
	}

	w := postLogin(h, url.Values{"username": {"admin"}, "password": {"wrong"}}, nil)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Incorrect username or password") {
		t.Fatalf("bad password = %d, want 401 with an error", w.Code)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("a failed login set a cookie")
	}

	w = postLogin(h, url.Values{"username": {"admin"}, "password": {"correct horse"}, "next": {"#/events"}}, nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/#/events" {
		t.Fatalf("good login = %d %q, want redirect to /#/events", w.Code, w.Header().Get("Location"))
	}
	c := sessionFrom(t, w)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("session cookie attributes too loose: %+v", c)
	}
	if w := get(h, "/api/health", c); w.Code != http.StatusOK {
		t.Fatalf("API with session = %d, want 200", w.Code)
	}
	if w := get(h, "/login", c); w.Code != http.StatusSeeOther {
		t.Fatalf("login page while signed in = %d, want redirect to the dashboard", w.Code)
	}
}

func TestLoginEscapesReflectedUsername(t *testing.T) {
	h := authedHandler(t, testHash(t, "pw"), "")
	w := postLogin(h, url.Values{"username": {`"><script>alert(1)</script>`}, "password": {"x"}}, nil)
	if strings.Contains(w.Body.String(), "<script>alert(1)") {
		t.Fatal("username reflected unescaped into the login page")
	}
}

func TestLoginRejectsOpenRedirectAndCrossSite(t *testing.T) {
	h := authedHandler(t, testHash(t, "pw"), "")
	good := url.Values{"username": {"admin"}, "password": {"pw"}}

	for _, next := range []string{"//evil.example", "/\\evil.example", "https://evil.example", "#/ok\r\nX: y"} {
		f := url.Values{"username": good["username"], "password": good["password"], "next": {next}}
		if loc := postLogin(h, f, nil).Header().Get("Location"); loc != "/" {
			t.Fatalf("next=%q redirected to %q, want /", next, loc)
		}
	}
	for name, mod := range map[string]func(*http.Request){
		"sec-fetch-site": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"origin":         func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
	} {
		if w := postLogin(h, good, mod); w.Code != http.StatusForbidden {
			t.Fatalf("%s cross-site login = %d, want 403", name, w.Code)
		}
	}
	same := func(r *http.Request) {
		r.Header.Set("Origin", "http://console.lan")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	if w := postLogin(h, good, same); w.Code != http.StatusSeeOther {
		t.Fatalf("same-origin login = %d, want 303", w.Code)
	}
	// Chrome's form post under a no-referrer policy: Origin is "null".
	nullOrigin := func(r *http.Request) {
		r.RemoteAddr = "192.0.2.8:5555" // fresh rate-limit bucket
		r.Header.Set("Origin", "null")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	if w := postLogin(h, good, nullOrigin); w.Code != http.StatusSeeOther {
		t.Fatalf("same-origin login with Origin: null = %d, want 303", w.Code)
	}
	// Without Sec-Fetch-Site, a mismatched Origin still refuses.
	oldBrowser := func(r *http.Request) { r.RemoteAddr = "192.0.2.8:5555"; r.Header.Set("Origin", "null") }
	if w := postLogin(h, good, oldBrowser); w.Code != http.StatusForbidden {
		t.Fatalf("Origin: null without Sec-Fetch-Site = %d, want 403", w.Code)
	}
}

func TestLoginRateLimitsGuessing(t *testing.T) {
	h := authedHandler(t, testHash(t, "pw"), "")
	bad := url.Values{"username": {"admin"}, "password": {"nope"}}
	for i := 0; i < 5; i++ {
		if w := postLogin(h, bad, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i+1, w.Code)
		}
	}
	// Even the right password is refused once the IP is out of attempts.
	if w := postLogin(h, url.Values{"username": {"admin"}, "password": {"pw"}}, nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt after burst = %d, want 429", w.Code)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	h := authedHandler(t, testHash(t, "pw"), "")
	c := sessionFrom(t, postLogin(h, url.Values{"username": {"admin"}, "password": {"pw"}}, nil))

	r := httptest.NewRequest("POST", "http://console.lan/api/logout", nil)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF header = %d, want 403", w.Code)
	}

	r = httptest.NewRequest("POST", "http://console.lan/api/logout", nil)
	r.AddCookie(c)
	r.Header.Set(csrfHeader, "1")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", w.Code)
	}
	if get(h, "/api/health", c).Code != http.StatusUnauthorized {
		t.Fatal("session still valid after logout")
	}
}

func TestSessionsSurviveRestartButNotPasswordChange(t *testing.T) {
	file := filepath.Join(t.TempDir(), "admin_sessions.json")
	hash := testHash(t, "pw")
	c := sessionFrom(t, postLogin(authedHandler(t, hash, file), url.Values{"username": {"admin"}, "password": {"pw"}}, nil))

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), c.Value) {
		t.Fatal("sessions file stores the raw token")
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0600 {
		t.Fatalf("sessions file mode %v, want 0600", fi.Mode().Perm())
	}

	if get(authedHandler(t, hash, file), "/api/health", c).Code != http.StatusOK {
		t.Fatal("session lost across restart")
	}
	if get(authedHandler(t, testHash(t, "new password"), file), "/api/health", c).Code != http.StatusUnauthorized {
		t.Fatal("session survived a password change")
	}
}

func TestNoAuthConfiguredSkipsLogin(t *testing.T) {
	h := authedHandler(t, "", "")
	if w := get(h, "/api/health", nil); w.Code != http.StatusOK {
		t.Fatalf("loopback-only API = %d, want 200", w.Code)
	}
	if w := get(h, "/login", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("login page with auth off = %d, want redirect", w.Code)
	}
}

// usersServer is a server with the given users, all with password "pw".
func usersServer(t *testing.T, sessions string, users ...config.AdminUser) (*Server, http.Handler) {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("abuse:\n  rate_limit:\n    burst: 15\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), cfg, AuthOptions{Users: users, SessionsPath: sessions})
	a, _ := NewAudit("")
	s.SetAudit(a)
	return s, s.Handler()
}

func signIn(t *testing.T, h http.Handler, name string) *http.Cookie {
	t.Helper()
	return sessionFrom(t, postLogin(h, url.Values{"username": {name}, "password": {"pw"}}, nil))
}

func TestAuditNamesSessionUser(t *testing.T) {
	hash := testHash(t, "pw")
	s, h := usersServer(t, "",
		config.AdminUser{Username: "pat", PasswordHash: hash, Role: config.RoleAdmin},
		config.AdminUser{Username: "bob", PasswordHash: hash, Role: config.RoleAdmin})
	c := signIn(t, h, "bob")

	r := httptest.NewRequest("POST", "http://console.lan/api/settings", strings.NewReader(`{"values":{"abuse.rate_limit.burst":30}}`))
	r.Header.Set(csrfHeader, "1")
	r.AddCookie(c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("settings save = %d %s, want 200", w.Code, w.Body)
	}
	got := s.audit.Load().Recent(10, time.Time{})
	if len(got) != 2 || got[0].Action != "settings_save" || got[0].User != "bob" {
		t.Fatalf("audit = %+v, want a login and a settings_save by bob", got)
	}
	if got[1].Action != "login" || got[1].User != "bob" {
		t.Fatalf("login entry = %+v, want user bob", got[1])
	}
}

func TestRemovedUserSessionEnds(t *testing.T) {
	hash := testHash(t, "pw")
	s, h := usersServer(t, "",
		config.AdminUser{Username: "pat", PasswordHash: hash, Role: config.RoleAdmin},
		config.AdminUser{Username: "bob", PasswordHash: hash, Role: config.RoleAdmin})
	c := signIn(t, h, "bob")
	if get(h, "/api/health", c).Code != http.StatusOK {
		t.Fatal("bob's session was refused before he was removed")
	}
	err := s.auth.users.update(func(us []config.AdminUser) ([]config.AdminUser, error) {
		return us[:1], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if w := get(h, "/api/health", c); w.Code != http.StatusUnauthorized {
		t.Fatalf("removed user's cookie = %d, want 401", w.Code)
	}
}

func TestPasswordChangeEndsSessions(t *testing.T) {
	hash := testHash(t, "pw")
	s, h := usersServer(t, "",
		config.AdminUser{Username: "pat", PasswordHash: hash, Role: config.RoleAdmin},
		config.AdminUser{Username: "bob", PasswordHash: hash, Role: config.RoleAdmin})
	bob, pat := signIn(t, h, "bob"), signIn(t, h, "pat")
	newHash := testHash(t, "other")
	err := s.auth.users.update(func(us []config.AdminUser) ([]config.AdminUser, error) {
		for i := range us {
			if us[i].Username == "bob" {
				us[i].PasswordHash = newHash
			}
		}
		return us, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if w := get(h, "/api/health", bob); w.Code != http.StatusUnauthorized {
		t.Fatalf("old cookie after a password change = %d, want 401", w.Code)
	}
	if w := get(h, "/api/health", pat); w.Code != http.StatusOK {
		t.Fatalf("another user's cookie = %d, want 200", w.Code)
	}
}

func TestLegacySessionSurvivesUpgrade(t *testing.T) {
	hash := testHash(t, "pw")
	file := filepath.Join(t.TempDir(), "admin_sessions.json")
	sum := sha256.Sum256([]byte(hash))
	token := "legacy-token"
	// today's format: no "user" field
	legacy := map[string]any{tokenKey(token): map[string]any{
		"created": time.Now().Add(-time.Hour),
		"expires": time.Now().Add(time.Hour),
		"ip":      "192.0.2.7",
		"pw":      hex.EncodeToString(sum[:8]),
	}}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}

	s, h := usersServer(t, file,
		config.AdminUser{Username: "pat", PasswordHash: hash, Role: config.RoleAdmin},
		config.AdminUser{Username: "vera", PasswordHash: testHash(t, "pw"), Role: config.RoleViewer})
	c := &http.Cookie{Name: sessionCookie, Value: token}
	r := httptest.NewRequest("GET", "http://console.lan/api/health", nil)
	r.AddCookie(c)
	var who config.AdminUser
	probe := s.auth.require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ = requestUser(r)
	}))
	w := httptest.NewRecorder()
	probe.ServeHTTP(w, r)
	if who.Username != "pat" {
		t.Fatalf("legacy session belongs to %q, want pat", who.Username)
	}
	if get(h, "/api/health", c).Code != http.StatusOK {
		t.Fatal("legacy session refused after the upgrade")
	}
	saved, _ := os.ReadFile(file)
	if !strings.Contains(string(saved), `"user":"pat"`) {
		t.Fatalf("saved sessions %s, want the session to name pat", saved)
	}
}

func TestLegacySessionWithoutMatchIsDropped(t *testing.T) {
	file := filepath.Join(t.TempDir(), "admin_sessions.json")
	legacy := map[string]any{tokenKey("old"): map[string]any{
		"created": time.Now().Add(-time.Hour),
		"expires": time.Now().Add(time.Hour),
		"ip":      "192.0.2.7",
		"pw":      "0000000000000000",
	}}
	data, _ := json.Marshal(legacy)
	os.WriteFile(file, data, 0600)
	_, h := usersServer(t, file, config.AdminUser{Username: "pat", PasswordHash: testHash(t, "pw"), Role: config.RoleAdmin})
	if w := get(h, "/api/health", &http.Cookie{Name: sessionCookie, Value: "old"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("legacy session with another password's fingerprint = %d, want 401", w.Code)
	}
}

func TestUnknownUserStillRunsBcrypt(t *testing.T) {
	_, h := usersServer(t, "", config.AdminUser{Username: "pat", PasswordHash: testHash(t, "pw"), Role: config.RoleAdmin})
	login := func(name, remote string) time.Duration {
		start := time.Now()
		postLogin(h, url.Values{"username": {name}, "password": {"wrong"}}, func(r *http.Request) { r.RemoteAddr = remote })
		return time.Since(start)
	}
	login("nobody", "192.0.2.50:1") // first call may build the dummy hash
	var known, unknown time.Duration
	for i := 0; i < 3; i++ {
		known += login("pat", "192.0.2.51:1")
		unknown += login("nobody", "192.0.2.52:1")
	}
	if unknown*2 < known {
		t.Fatalf("unknown user took %v against %v for a wrong password: bcrypt is skipped", unknown, known)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, os.ErrClosed }

// An unknown username must cost a full bcrypt run whatever happens while the
// dummy hash is built, or the time a login takes tells which names exist.
func TestDummyHashNeverEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		hash []byte
	}{
		{"generated", dummyHash()},
		{"random source fails", buildDummyHash(failingReader{})},
		{"fallback literal", []byte(dummyFallback)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cost, err := bcrypt.Cost(tc.hash)
			if err != nil || cost != bcrypt.DefaultCost {
				t.Fatalf("dummy hash %q: cost %d, err %v; want a valid hash at cost %d", tc.hash, cost, err, bcrypt.DefaultCost)
			}
			if err := bcrypt.CompareHashAndPassword(tc.hash, []byte("guess")); err != bcrypt.ErrMismatchedHashAndPassword {
				t.Fatalf("compare against dummy hash = %v, want a mismatch after a full run", err)
			}
		})
	}
}

const signInUnavailable = "Sign-in is unavailable: the users file can't be loaded. Fix it, or run loupe -setup-admin, and try again."

// lockedServer is a console started as main does when admin.auth_file is set
// but failed to load: the path, no users, and the startup error.
func lockedServer(t *testing.T, authFile string) (*Server, http.Handler) {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	s := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), cfg, AuthOptions{
		File:      authFile,
		LoadError: "admin.auth_file: " + authFile + ": could not load",
	})
	if s.auth == nil {
		t.Fatal("a configured users file that failed to load gave no auth: the console would be open to anyone")
	}
	return s, s.Handler()
}

func wantLocked(t *testing.T, h http.Handler, authFile string) {
	t.Helper()
	w := postLogin(h, url.Values{"username": {"pat"}, "password": {"correct horse"}}, nil)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), template.HTMLEscapeString(signInUnavailable)) {
		t.Fatalf("POST /login = %d %s, want 503 saying sign-in is unavailable", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), authFile) || strings.Contains(w.Body.String(), "yaml") {
		t.Errorf("login page leaks the path or parser detail: %s", w.Body)
	}
	if hasSession(w) {
		t.Error("a locked console set a session cookie")
	}
	for _, p := range []string{"/api/settings", "/api/health", "/api/me"} {
		if w := get(h, p, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s on a locked console = %d, want 401", p, w.Code)
		}
	}
	if w := get(h, "/", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("GET / on a locked console = %d %q, want a redirect to /login", w.Code, w.Header().Get("Location"))
	}
}

func TestBrokenAuthFileLocksConsole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_auth.yaml")
	if err := os.WriteFile(path, []byte("users: [unclosed"), 0600); err != nil {
		t.Fatal(err)
	}
	s, h := lockedServer(t, path)
	clock := time.Now()
	s.auth.users.now = func() time.Time { return clock }
	wantLocked(t, h, path)
	// The store has now read the broken file itself, and must keep looking.
	clock = clock.Add(userReloadEvery)
	wantLocked(t, h, path)
	if got := s.auth.users.loadError(); !strings.Contains(got, "yaml") {
		t.Errorf("store load error = %q, want its own reading of the broken file", got)
	}

	// The operator fixes the file; sign-in works within a second, no restart.
	hash := testHash(t, "correct horse")
	if err := config.SaveAdminAuth(path, &config.AdminAuth{Users: []config.AdminUser{{Username: "pat", PasswordHash: hash, Role: config.RoleAdmin}}}); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(userReloadEvery)
	w := postLogin(h, url.Values{"username": {"pat"}, "password": {"correct horse"}}, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login after the fix = %d %s, want 303", w.Code, w.Body)
	}
	if got := get(h, "/api/settings", sessionFrom(t, w)); got.Code == http.StatusUnauthorized {
		t.Fatalf("GET /api/settings with the new session = %d, want it let through", got.Code)
	}
}

func TestMissingAuthFileNeverMeansNoAuth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_auth.yaml") // never created
	if a := newAuth(AuthOptions{File: path}); a == nil {
		t.Fatal("newAuth with a users file and no users = nil, which means no auth")
	}
	if a := newAuth(AuthOptions{}); a != nil {
		t.Fatal("newAuth with no users file and no users must stay nil (loopback no-auth)")
	}
	s, h := lockedServer(t, path)
	if got := s.auth.users.loadError(); got == "" {
		t.Error("the store does not report the startup load error")
	}
	wantLocked(t, h, path)
}

// A password longer than bcrypt's 72 bytes signs in, and only in full.
func TestLongPasswordSignsIn(t *testing.T) {
	long := strings.Repeat("correct horse battery staple ", 4) // 116 characters
	hash, err := config.HashPassword(long)
	if err != nil {
		t.Fatal(err)
	}
	h := authedHandler(t, hash, "")
	if w := postLogin(h, url.Values{"username": {"admin"}, "password": {long}}, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("login with the full 116-character password = %d, want 303", w.Code)
	}
	cut := long[:72] + "something else entirely"
	if w := postLogin(h, url.Values{"username": {"admin"}, "password": {cut}}, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("login sharing only the first 72 bytes = %d, want 401", w.Code)
	}
}
