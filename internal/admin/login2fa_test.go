package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/ratelimit"
)

const (
	timedOutText = "Your sign-in timed out. Enter your password again."
	wrongText    = "That code didn&#39;t work. Try the newest one from your app."
)

// tfa is a server with one TOTP user (pat) and a clock the test moves.
type tfa struct {
	t      *testing.T
	s      *Server
	h      http.Handler
	secret []byte
	codes  []string // pat's recovery codes
	clock  time.Time
	mu     sync.Mutex
}

func newTFA(t *testing.T, require2FA bool, extra ...config.AdminUser) *tfa {
	t.Helper()
	secret, err := newTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	hash := testHash(t, "pw")
	users := append([]config.AdminUser{{
		Username: "pat", PasswordHash: hash, Role: config.RoleAdmin,
		TOTPSecret: encodeTOTPSecret(secret), RecoveryHashes: hashes,
	}}, extra...)
	for i := range users[1:] {
		users[i+1].PasswordHash = hash
	}
	s, h := usersServer(t, "", users...)
	f := &tfa{t: t, s: s, h: h, secret: secret, codes: codes, clock: time.Unix(1_800_000_000, 0)}
	s.auth.require2FA = require2FA
	s.auth.now = f.now
	s.auth.users.now = f.now
	// The tests make far more sign-in posts from one address than the real
	// limits allow.
	s.auth.attempts = ratelimit.New(1000, 1000)
	s.auth.global = ratelimit.New(1000, 1000)
	return f
}

func (f *tfa) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clock
}

func (f *tfa) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = f.clock.Add(d)
}

// code is the current valid TOTP code, or the one n steps ahead.
func (f *tfa) code(n int64) string {
	return totpCode(f.secret, f.now().Unix()/30+n)
}

func (f *tfa) post(path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://console.lan"+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "192.0.2.7:5555"
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

var pendingRe = regexp.MustCompile(`name="pending" value="([^"]+)"`)

// password signs pat in with her password and returns the pending token.
func (f *tfa) password() string {
	f.t.Helper()
	w := f.post("/login", url.Values{"username": {"pat"}, "password": {"pw"}})
	if w.Code != http.StatusOK {
		f.t.Fatalf("password stage = %d, want 200 with the code form", w.Code)
	}
	m := pendingRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		f.t.Fatalf("no pending field in the code stage: %s", w.Body)
	}
	return m[1]
}

func (f *tfa) second(pending, code string) *httptest.ResponseRecorder {
	return f.post("/login/2fa", url.Values{"pending": {pending}, "code": {code}})
}

func hasSession(w *httptest.ResponseRecorder) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return true
		}
	}
	return false
}

func TestTwoStageLogin(t *testing.T) {
	f := newTFA(t, false)
	w := f.post("/login", url.Values{"username": {"pat"}, "password": {"pw"}, "next": {"#/bots"}})
	if w.Code != http.StatusOK || len(w.Result().Cookies()) != 0 {
		t.Fatalf("password stage = %d with cookies %v, want 200 and none", w.Code, w.Result().Cookies())
	}
	body := w.Body.String()
	for _, want := range []string{
		`action="/login/2fa"`, `name="code"`, `autocomplete="one-time-code"`, `inputmode="text"`,
		`maxlength="32"`, `autofocus`, `name="next" id="next" value="#/bots"`,
		"Enter the 6-digit code from your authenticator app, or one of your recovery codes.",
		`href="/login"`, "Start over",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("code stage lacks %q", want)
		}
	}
	if strings.Contains(body, `name="password"`) {
		t.Error("code stage still asks for the password")
	}
	if got := f.s.audit.Load().Recent(10, time.Time{}); len(got) != 0 {
		t.Fatalf("audit after the password stage = %+v, want nothing", got)
	}

	pending := pendingRe.FindStringSubmatch(body)[1]
	w = f.second(pending, f.code(0))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("code stage = %d to %q, want 303 to /", w.Code, w.Header().Get("Location"))
	}
	c := sessionFrom(t, w)
	if w := get(f.h, "/api/settings", c); w.Code != http.StatusOK {
		t.Fatalf("GET /api/settings with the new session = %d, want 200", w.Code)
	}
	got := f.s.audit.Load().Recent(10, time.Time{})
	if len(got) != 1 || got[0].Action != "login" || got[0].User != "pat" || got[0].Detail != "authenticator app" {
		t.Fatalf("audit = %+v, want one login by pat via authenticator app", got)
	}
	// The token is spent.
	if w := f.second(pending, f.code(1)); w.Code != http.StatusUnauthorized || hasSession(w) {
		t.Fatalf("spent pending token = %d (session %v), want 401 and no session", w.Code, hasSession(w))
	}
}

func TestTwoStageLoginKeepsNext(t *testing.T) {
	f := newTFA(t, false)
	p := f.password()
	w := f.post("/login/2fa", url.Values{"pending": {p}, "code": {f.code(0)}, "next": {"#/bots"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/#/bots" {
		t.Fatalf("code stage = %d to %q, want 303 to /#/bots", w.Code, w.Header().Get("Location"))
	}
}

func TestPendingTokenExpires(t *testing.T) {
	f := newTFA(t, false)
	p := f.password()
	f.advance(5*time.Minute + time.Second)
	w := f.second(p, f.code(0))
	if w.Code != http.StatusUnauthorized || hasSession(w) {
		t.Fatalf("expired pending = %d (session %v), want 401 and no session", w.Code, hasSession(w))
	}
	if body := w.Body.String(); !strings.Contains(body, timedOutText) || !strings.Contains(body, `name="password"`) {
		t.Fatalf("expired pending body lacks the timed-out text or the password stage: %s", body)
	}
}

func TestPendingTokenUnknown(t *testing.T) {
	f := newTFA(t, false)
	for _, p := range []string{"", "nonsense"} {
		w := f.second(p, f.code(0))
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), timedOutText) {
			t.Errorf("pending %q = %d, want 401 timed out", p, w.Code)
		}
	}
}

func TestPendingTokenGivesUpAfterFiveWrongCodes(t *testing.T) {
	f := newTFA(t, false)
	p := f.password()
	for i := 1; i <= 4; i++ {
		w := f.second(p, "000000")
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), wrongText) || !strings.Contains(w.Body.String(), `name="code"`) {
			t.Fatalf("wrong code %d = %d, want 401 with the code stage and the wrong-code text: %s", i, w.Code, w.Body)
		}
	}
	w := f.second(p, "000000")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Too many wrong codes. Enter your password again.") ||
		!strings.Contains(w.Body.String(), `name="password"`) {
		t.Fatalf("fifth wrong code = %d, want 401 with the password stage: %s", w.Code, w.Body)
	}
	w = f.second(p, f.code(0))
	if w.Code != http.StatusUnauthorized || hasSession(w) || !strings.Contains(w.Body.String(), `name="password"`) {
		t.Fatalf("right code after five wrong = %d (session %v), want 401 password stage", w.Code, hasSession(w))
	}
	// Each wrong code was recorded as a failed sign-in for pat.
	got := f.s.audit.Load().Recent(10, time.Time{})
	if len(got) != 1 || got[0].Action != "login_failed" || got[0].Target != "pat" || got[0].Detail != "second factor" || got[0].Count != 5 {
		t.Fatalf("failed sign-ins = %+v, want one run of 5 for pat (second factor)", got)
	}
}

func TestPendingTokenIsBoundToPassword(t *testing.T) {
	f := newTFA(t, false)
	p := f.password()
	err := f.s.auth.users.update(func(us []config.AdminUser) ([]config.AdminUser, error) {
		us[0].PasswordHash = testHash(t, "new")
		return us, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if w := f.second(p, f.code(0)); w.Code != http.StatusUnauthorized || hasSession(w) {
		t.Fatalf("code after a password change = %d (session %v), want 401 and no session", w.Code, hasSession(w))
	}
}

func TestPendingTokenDiesWhenTOTPIsReset(t *testing.T) {
	f := newTFA(t, false)
	p := f.password()
	err := f.s.auth.users.update(func(us []config.AdminUser) ([]config.AdminUser, error) {
		us[0].TOTPSecret, us[0].RecoveryHashes = "", nil
		return us, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// An empty secret must never be a key that any code matches.
	for _, code := range []string{f.code(0), totpCode(nil, f.now().Unix()/30)} {
		if w := f.second(p, code); w.Code != http.StatusUnauthorized || hasSession(w) {
			t.Fatalf("code after reset-2fa = %d (session %v), want 401 and no session", w.Code, hasSession(w))
		}
	}
}

func TestTOTPRejectsReplayAtLogin(t *testing.T) {
	f := newTFA(t, false)
	code := f.code(0)
	if w := f.second(f.password(), code); w.Code != http.StatusSeeOther {
		t.Fatalf("first use = %d, want 303", w.Code)
	}
	f.advance(5 * time.Second)
	if code != f.code(0) {
		t.Skip("clock crossed a 30s step")
	}
	if w := f.second(f.password(), code); w.Code != http.StatusUnauthorized || hasSession(w) {
		t.Fatalf("replayed code = %d (session %v), want 401 and no session", w.Code, hasSession(w))
	}
}

func TestRecoveryCodeLogsInOnce(t *testing.T) {
	f := newTFA(t, false)
	code := strings.ToUpper(f.codes[0]) // typed in upper case
	w := f.second(f.password(), code)
	if w.Code != http.StatusSeeOther || !hasSession(w) {
		t.Fatalf("recovery code = %d, want 303 with a session: %s", w.Code, w.Body)
	}
	got := f.s.audit.Load().Recent(10, time.Time{})
	if len(got) != 1 || got[0].Action != "login" || got[0].Detail != "recovery code (9 left)" {
		t.Fatalf("audit = %+v, want a login with detail recovery code (9 left)", got)
	}
	if w := f.second(f.password(), f.codes[0]); w.Code != http.StatusUnauthorized || hasSession(w) {
		t.Fatalf("recovery code reused = %d (session %v), want 401 and no session", w.Code, hasSession(w))
	}
	// Another one still works.
	if w := f.second(f.password(), strings.ReplaceAll(f.codes[1], "-", "")); w.Code != http.StatusSeeOther {
		t.Fatalf("second recovery code = %d, want 303", w.Code)
	}
}

func TestSameCodeTwiceSignsInOnce(t *testing.T) {
	for _, tc := range []struct {
		name string
		code func(f *tfa) string
	}{
		{"totp", func(f *tfa) string { return f.code(0) }},
		{"recovery", func(f *tfa) string { return f.codes[0] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTFA(t, false)
			pendings := []string{f.password(), f.password()}
			code := tc.code(f)

			codes := make([]int, len(pendings))
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i, p := range pendings {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					codes[i] = f.second(p, code).Code
				}()
			}
			close(start)
			wg.Wait()

			n := 0
			for _, c := range codes {
				if c == http.StatusSeeOther {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("statuses %v: %d sign-ins with one code sent twice, want exactly 1", codes, n)
			}
		})
	}
}

func TestOnePendingSeveralCodesSignsInOnce(t *testing.T) {
	f := newTFA(t, false)
	// Codes of different steps don't stop each other at the store, which lets
	// them all through whenever they arrive in step order. Only the pending
	// token can refuse the rest, so repeat until the scheduler tests that.
	for round := 0; round < 20; round++ {
		f.advance(2 * time.Minute) // past every step used so far
		p := f.password()
		codes := []string{f.code(-1), f.code(0), f.code(1)}
		got := make([]int, len(codes))
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i, c := range codes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				got[i] = f.second(p, c).Code
			}()
		}
		close(start)
		wg.Wait()
		n := 0
		for _, c := range got {
			if c == http.StatusSeeOther {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("round %d: statuses %v: %d sign-ins from one pending token, want exactly 1", round, got, n)
		}
	}
}

func TestPendingTableIsBounded(t *testing.T) {
	f := newTFA(t, false)
	first := f.password()
	for i := 0; i < maxPending+10; i++ {
		f.advance(time.Millisecond)
		f.password()
	}
	a := f.s.auth
	a.pmu.Lock()
	n := len(a.pending)
	a.pmu.Unlock()
	if n > maxPending {
		t.Fatalf("%d pending sign-ins held, want at most %d", n, maxPending)
	}
	// The oldest went first.
	if w := f.second(first, f.code(0)); w.Code != http.StatusUnauthorized {
		t.Fatalf("oldest pending after overflow = %d, want 401", w.Code)
	}
}

func TestRequire2FABlocksUnenrolledLogin(t *testing.T) {
	f := newTFA(t, true, config.AdminUser{Username: "vera", Role: config.RoleAdmin})
	w := f.post("/login", url.Values{"username": {"vera"}, "password": {"pw"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("unenrolled login = %d, want 303", w.Code)
	}
	c := sessionFrom(t, w)
	if w := get(f.h, "/api/settings", c); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "two-factor enrolment required") {
		t.Fatalf("GET /api/settings = %d %q, want 403 two-factor enrolment required", w.Code, w.Body)
	}
	if w := get(f.h, "/", c); w.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", w.Code)
	}
	r := httptest.NewRequest("POST", "http://console.lan/api/logout", nil)
	r.Header.Set(csrfHeader, "1")
	r.AddCookie(c)
	lw := httptest.NewRecorder()
	f.h.ServeHTTP(lw, r)
	if lw.Code != http.StatusNoContent {
		t.Fatalf("POST /api/logout = %d, want 204", lw.Code)
	}
}

func TestRequire2FAEnrolmentTakesEffectAtOnce(t *testing.T) {
	f := newTFA(t, true, config.AdminUser{Username: "vera", Role: config.RoleAdmin})
	c := sessionFrom(t, f.post("/login", url.Values{"username": {"vera"}, "password": {"pw"}}))
	if w := get(f.h, "/api/settings", c); w.Code != http.StatusForbidden {
		t.Fatalf("before enrolling = %d, want 403", w.Code)
	}
	err := f.s.auth.users.update(func(us []config.AdminUser) ([]config.AdminUser, error) {
		for i := range us {
			if us[i].Username == "vera" {
				us[i].TOTPSecret = encodeTOTPSecret(f.secret)
			}
		}
		return us, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if w := get(f.h, "/api/settings", c); w.Code != http.StatusOK {
		t.Fatalf("after enrolling = %d, want 200", w.Code)
	}
}

func TestRequire2FALetsEnrolledUserThrough(t *testing.T) {
	f := newTFA(t, true)
	w := f.second(f.password(), f.code(0))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("sign-in = %d, want 303", w.Code)
	}
	if w := get(f.h, "/api/settings", sessionFrom(t, w)); w.Code != http.StatusOK {
		t.Fatalf("enrolled user GET /api/settings = %d, want 200", w.Code)
	}
}

func TestAllowRequire2FAByRoute(t *testing.T) {
	f := newTFA(t, true, config.AdminUser{Username: "vera", Role: config.RoleAdmin})
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	vera := config.AdminUser{Username: "vera", Role: config.RoleAdmin}
	for _, tc := range []struct {
		name string
		rt   route
		want int
	}{
		{"self route", route{pattern: "GET /api/me", access: "self"}, 200},
		{"dashboard page", route{pattern: "GET /{$}"}, 200},
		{"plain read", route{pattern: "GET /api/stats"}, 403},
		{"write", route{pattern: "POST /api/settings"}, 403},
		{"admin read", route{pattern: "GET /api/users", access: "admin"}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			f.s.allow(tc.rt, ok)(w, withUser(httptest.NewRequest("GET", "/x", nil), vera))
			if w.Code != tc.want {
				t.Fatalf("%s = %d, want %d", tc.rt.pattern, w.Code, tc.want)
			}
		})
	}
}

func TestLoginWithoutTOTPUnchanged(t *testing.T) {
	f := newTFA(t, false, config.AdminUser{Username: "vera", Role: config.RoleAdmin})
	w := f.post("/login", url.Values{"username": {"vera"}, "password": {"pw"}})
	if w.Code != http.StatusSeeOther || !hasSession(w) {
		t.Fatalf("login without TOTP = %d (session %v), want 303 with a session", w.Code, hasSession(w))
	}
	if w := get(f.h, "/api/settings", sessionFrom(t, w)); w.Code != http.StatusOK {
		t.Fatalf("GET /api/settings = %d, want 200", w.Code)
	}
}

func TestSecondFactorIsRateLimited(t *testing.T) {
	f := newTFA(t, false)
	p := f.password()
	f.s.auth.attempts = ratelimit.New(0.001, 2)
	f.s.auth.global = ratelimit.New(1000, 1000)
	for i := 0; i < 2; i++ {
		f.second(p, "000000")
	}
	w := f.second(p, f.code(0))
	if w.Code != http.StatusTooManyRequests || hasSession(w) || w.Header().Get("Retry-After") == "" {
		t.Fatalf("third try past the limit = %d (session %v), want 429 without a session", w.Code, hasSession(w))
	}
	if !strings.Contains(w.Body.String(), `name="code"`) {
		t.Error("rate-limited page dropped the code form, so the user can't retry")
	}
}

func TestSecondFactorRefusesCrossSite(t *testing.T) {
	f := newTFA(t, false)
	p := f.password()
	r := httptest.NewRequest("POST", "http://console.lan/login/2fa", strings.NewReader(url.Values{"pending": {p}, "code": {f.code(0)}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || hasSession(w) {
		t.Fatalf("cross-site /login/2fa = %d, want 403 and no session", w.Code)
	}
}
