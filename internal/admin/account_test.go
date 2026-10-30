package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
)

// acct is a server whose users live in a real file, so tests can see what was
// saved. Everyone's password is "pw".
type acct struct {
	t     *testing.T
	s     *Server
	h     http.Handler
	file  string
	clock time.Time
}

func newAcct(t *testing.T, users ...config.AdminUser) *acct {
	t.Helper()
	hash := testHash(t, "pw")
	for i := range users {
		users[i].PasswordHash = hash
	}
	file := filepath.Join(t.TempDir(), "admin_auth.yaml")
	if err := config.SaveAdminAuth(file, &config.AdminAuth{Users: users}); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	s := NewServer(newTestStore(t, 10), reputation.New(reputation.Config{}), cfg, AuthOptions{File: file, Users: users})
	a, _ := NewAudit("")
	s.SetAudit(a)
	f := &acct{t: t, s: s, h: s.Handler(), file: file, clock: time.Unix(1_800_000_000, 0)}
	s.auth.now = func() time.Time { return f.clock }
	return f
}

func (f *acct) signIn(name string) *http.Cookie {
	f.t.Helper()
	return signIn(f.t, f.h, name)
}

func (f *acct) do(method, path, body string, c *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://console.lan"+path, strings.NewReader(body))
	r.Header.Set(csrfHeader, "1")
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

func (f *acct) post(path, body string, c *http.Cookie) *httptest.ResponseRecorder {
	return f.do("POST", path, body, c)
}

// fileUser is the user as saved on disk.
func (f *acct) fileUser(name string) config.AdminUser {
	f.t.Helper()
	a, err := config.LoadAdminAuth(f.file)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, u := range a.Users {
		if u.Username == name {
			return u
		}
	}
	f.t.Fatalf("%s is not in the users file", name)
	return config.AdminUser{}
}

func (f *acct) audits(action string) []AuditEntry {
	var out []AuditEntry
	for _, e := range f.s.audit.Load().Recent(100, time.Time{}) {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func (f *acct) me(c *http.Cookie) map[string]any {
	f.t.Helper()
	w := f.do("GET", "/api/me", "", c)
	if w.Code != http.StatusOK {
		f.t.Fatalf("GET /api/me = %d %s, want 200", w.Code, w.Body)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		f.t.Fatalf("/api/me is not JSON: %v: %s", err, w.Body)
	}
	return m
}

func wantStatus(t *testing.T, w *httptest.ResponseRecorder, code int, text string) {
	t.Helper()
	if w.Code != code || !strings.Contains(w.Body.String(), text) {
		t.Fatalf("got %d %q, want %d containing %q", w.Code, w.Body, code, text)
	}
}

func twoUsers(t *testing.T) *acct {
	return newAcct(t,
		config.AdminUser{Username: "pat", Role: config.RoleAdmin},
		config.AdminUser{Username: "vera", Role: config.RoleViewer})
}

// enrol begins and confirms an enrolment for the cookie's user and returns the
// secret and the recovery codes.
func (f *acct) enrol(c *http.Cookie) ([]byte, []string) {
	f.t.Helper()
	w := f.post("/api/account/2fa/begin", "", c)
	if w.Code != http.StatusOK {
		f.t.Fatalf("begin = %d %s, want 200", w.Code, w.Body)
	}
	var b struct{ Secret, URI string }
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || b.Secret == "" {
		f.t.Fatalf("begin body = %q (%v), want a secret", w.Body, err)
	}
	secret, err := decodeTOTPSecret(b.Secret)
	if err != nil {
		f.t.Fatal(err)
	}
	w = f.post("/api/account/2fa/confirm", `{"code":"`+totpCode(secret, f.clock.Unix()/30)+`"}`, c)
	if w.Code != http.StatusOK {
		f.t.Fatalf("confirm = %d %s, want 200", w.Code, w.Body)
	}
	var r struct {
		Codes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		f.t.Fatal(err)
	}
	return secret, r.Codes
}

func TestMeReportsRoleAndTOTP(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("vera")
	m := f.me(c)
	if m["user"] != "vera" || m["role"] != "viewer" || m["totp"] != false || m["recovery_left"] != float64(0) ||
		m["require_2fa"] != false || m["auth"] != true {
		t.Fatalf("/api/me = %v, want vera, viewer, no totp, 0 left, not required, auth on", m)
	}
	f.s.auth.require2FA = true
	if f.me(c)["require_2fa"] != true {
		t.Fatal("require_2fa should follow the console setting")
	}
	if w := f.do("GET", "/api/me", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("/api/me without a session = %d, want 401", w.Code)
	}
}

func TestAccountsOffWithoutAuth(t *testing.T) {
	s := NewServer(newTestStore(t, 10), nil, "", AuthOptions{})
	h := s.Handler()
	do := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://console.lan"+path, nil)
		r.Header.Set(csrfHeader, "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := do("GET", "/api/me")
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil || w.Code != 200 || m["auth"] != false || m["role"] != "admin" {
		t.Fatalf("/api/me = %d %s, want auth:false role:admin", w.Code, w.Body)
	}
	for _, rt := range s.routes() {
		if !strings.Contains(rt.pattern, "/api/account/") && !strings.Contains(rt.pattern, "/api/users") {
			continue
		}
		method, path, _ := strings.Cut(rt.pattern, " ")
		wantStatus(t, do(method, path), 404, "accounts are off (no admin.auth_file)")
	}
}

func TestAccountPasswordChangeKeepsCurrentSession(t *testing.T) {
	f := twoUsers(t)
	old := f.signIn("pat")
	other := f.signIn("vera")

	wantStatus(t, f.post("/api/account/password", `{"current":"wrong","new":"brand new pass"}`, old), 403, "incorrect password")
	if get(f.h, "/api/health", old).Code != http.StatusOK {
		t.Fatal("a refused change ended the session")
	}

	w := f.post("/api/account/password", `{"current":"pw","new":"brand new pass"}`, old)
	if w.Code != http.StatusNoContent {
		t.Fatalf("password change = %d %s, want 204", w.Code, w.Body)
	}
	fresh := sessionFrom(t, w)
	if get(f.h, "/api/health", fresh).Code != http.StatusOK {
		t.Fatal("the cookie from the change was refused")
	}
	if w := get(f.h, "/api/health", old); w.Code != http.StatusUnauthorized {
		t.Fatalf("old cookie after the change = %d, want 401", w.Code)
	}
	if get(f.h, "/api/health", other).Code != http.StatusOK {
		t.Fatal("changing pat's password ended vera's session")
	}
	if w := postLogin(f.h, map[string][]string{"username": {"pat"}, "password": {"brand new pass"}}, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("login with the new password = %d, want 303", w.Code)
	}
	if e := f.audits("password_change"); len(e) != 1 || e[0].Target != "pat" {
		t.Fatalf("audit = %+v, want one password_change for pat", e)
	}
}

func TestAccountPasswordRejectsBadNewPassword(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("pat")
	for _, tc := range []struct {
		name, new string
		want      string
	}{
		{"short", "seven77", "password must be 8 to 256 characters"},
		{"empty", "", "password must be 8 to 256 characters"},
		{"257 chars", strings.Repeat("x", 257), "password must be 8 to 256 characters"},
		{"huge", strings.Repeat("x", 1025), "password must be 8 to 256 characters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"current": "pw", "new": tc.new})
			wantStatus(t, f.post("/api/account/password", string(body), c), 400, tc.want)
		})
	}
	wantStatus(t, f.post("/api/account/password", `not json`, c), 400, "")
	if get(f.h, "/api/health", c).Code != http.StatusOK {
		t.Fatal("refused changes ended the session")
	}
}

func TestViewerCanChangeOwnPassword(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("vera")
	w := f.post("/api/account/password", `{"current":"pw","new":"brand new pass"}`, c)
	if w.Code != http.StatusNoContent {
		t.Fatalf("viewer password change = %d %s, want 204", w.Code, w.Body)
	}
}

func TestEnrolConfirmReturnsTenCodes(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("vera")
	secret, codes := f.enrol(c)
	if len(codes) != 10 {
		t.Fatalf("got %d recovery codes, want 10", len(codes))
	}
	m := f.me(c)
	if m["totp"] != true || m["recovery_left"] != float64(10) {
		t.Fatalf("/api/me = %v, want totp:true recovery_left:10", m)
	}
	u := f.fileUser("vera")
	if u.TOTPSecret != encodeTOTPSecret(secret) || len(u.RecoveryHashes) != 10 || u.TOTPLastStep != f.clock.Unix()/30 {
		t.Fatalf("file holds secret %q step %d with %d hashes, want the confirmed secret, step %d and 10 hashes",
			u.TOTPSecret, u.TOTPLastStep, len(u.RecoveryHashes), f.clock.Unix()/30)
	}
	for _, code := range codes {
		if _, ok := matchRecoveryCode(u.RecoveryHashes, code); !ok {
			t.Fatalf("recovery code %q matches none of the stored hashes", code)
		}
	}
	if e := f.audits("2fa_enable"); len(e) != 1 || e[0].Target != "vera" || e[0].User != "vera" {
		t.Fatalf("audit = %+v, want one 2fa_enable for vera", e)
	}
	// The same code can't be used to sign in right after enrolling.
	if _, ok := checkTOTP(secret, totpCode(secret, f.clock.Unix()/30), f.clock, u.TOTPLastStep); ok {
		t.Fatal("the enrolment code is still usable at sign-in")
	}
}

func TestEnrolBeginOnlyHoldsSecretInMemory(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("vera")
	w := f.post("/api/account/2fa/begin", "", c)
	var b struct{ Secret, URI string }
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || !strings.HasPrefix(b.URI, "otpauth://totp/Loupe:vera?secret="+b.Secret) {
		t.Fatalf("begin = %d %s, want a secret and its otpauth uri", w.Code, w.Body)
	}
	if f.fileUser("vera").TOTPSecret != "" {
		t.Fatal("begin saved the secret")
	}
	if len(f.audits("2fa_enable")) != 0 {
		t.Fatal("begin was audited as an enable")
	}
}

func TestEnrolConfirmWrongCode(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("vera")
	f.post("/api/account/2fa/begin", "", c)
	wantStatus(t, f.post("/api/account/2fa/confirm", `{"code":"000000"}`, c), 400, "that code didn't work")
	if u := f.fileUser("vera"); u.TOTPSecret != "" || len(u.RecoveryHashes) != 0 {
		t.Fatalf("a wrong code stored %+v", u)
	}
	if f.me(c)["totp"] != false || len(f.audits("2fa_enable")) != 0 {
		t.Fatal("a wrong code turned two-factor on or was audited")
	}
}

func TestEnrolConfirmNeedsFreshBegin(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("vera")
	wantStatus(t, f.post("/api/account/2fa/confirm", `{"code":"123456"}`, c), 409, "start enrolment again")

	w := f.post("/api/account/2fa/begin", "", c)
	var b struct{ Secret string }
	json.Unmarshal(w.Body.Bytes(), &b)
	secret, _ := decodeTOTPSecret(b.Secret)
	f.clock = f.clock.Add(10*time.Minute + time.Second)
	code := totpCode(secret, f.clock.Unix()/30)
	wantStatus(t, f.post("/api/account/2fa/confirm", `{"code":"`+code+`"}`, c), 409, "start enrolment again")
	if f.fileUser("vera").TOTPSecret != "" {
		t.Fatal("an expired enrolment was stored")
	}

	// A second begin replaces the first, and a secret is used once.
	f.post("/api/account/2fa/begin", "", c)
	w = f.post("/api/account/2fa/begin", "", c)
	json.Unmarshal(w.Body.Bytes(), &b)
	second, _ := decodeTOTPSecret(b.Secret)
	wantStatus(t, f.post("/api/account/2fa/confirm", `{"code":"`+totpCode(secret, f.clock.Unix()/30)+`"}`, c), 400, "that code didn't work")
	if w := f.post("/api/account/2fa/confirm", `{"code":"`+totpCode(second, f.clock.Unix()/30)+`"}`, c); w.Code != 200 {
		t.Fatalf("confirm with the latest secret = %d %s, want 200", w.Code, w.Body)
	}
	wantStatus(t, f.post("/api/account/2fa/confirm", `{"code":"`+totpCode(second, f.clock.Unix()/30)+`"}`, c), 409, "")
}

func TestEnrolmentsAreKeptPerUser(t *testing.T) {
	f := twoUsers(t)
	p, v := f.signIn("pat"), f.signIn("vera")
	w := f.post("/api/account/2fa/begin", "", p)
	var b struct{ Secret string }
	json.Unmarshal(w.Body.Bytes(), &b)
	secret, _ := decodeTOTPSecret(b.Secret)
	// Vera never began, so pat's secret can't be confirmed from her session.
	wantStatus(t, f.post("/api/account/2fa/confirm", `{"code":"`+totpCode(secret, f.clock.Unix()/30)+`"}`, v), 409, "start enrolment again")
}

func TestEnrolBeginRefusedWhileEnrolled(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("vera")
	f.enrol(c)
	// Replacing the authenticator must go through disable, which asks for the password.
	wantStatus(t, f.post("/api/account/2fa/begin", "", c), 409, "")
}

func TestDisable2FARequiresPassword(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("vera")
	f.enrol(c)

	wantStatus(t, f.post("/api/account/2fa/disable", `{"password":"wrong"}`, c), 403, "incorrect password")
	if f.fileUser("vera").TOTPSecret == "" {
		t.Fatal("a wrong password turned two-factor off")
	}

	f.s.auth.require2FA = true
	wantStatus(t, f.post("/api/account/2fa/disable", `{"password":"pw"}`, c), 409, "two-factor is required on this console")
	if f.fileUser("vera").TOTPSecret == "" {
		t.Fatal("disable worked while two-factor is required")
	}

	f.s.auth.require2FA = false
	if w := f.post("/api/account/2fa/disable", `{"password":"pw"}`, c); w.Code != http.StatusNoContent {
		t.Fatalf("disable = %d %s, want 204", w.Code, w.Body)
	}
	u := f.fileUser("vera")
	if u.TOTPSecret != "" || u.TOTPLastStep != 0 || len(u.RecoveryHashes) != 0 {
		t.Fatalf("after disable the file holds %+v", u)
	}
	if e := f.audits("2fa_disable"); len(e) != 1 || e[0].Target != "vera" {
		t.Fatalf("audit = %+v, want one 2fa_disable for vera", e)
	}
	wantStatus(t, f.post("/api/account/2fa/disable", `{"password":"pw"}`, c), 409, "")
}

func TestRecoveryRegenerate(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("vera")
	wantStatus(t, f.post("/api/account/recovery", `{"password":"pw"}`, c), 409, "")
	_, old := f.enrol(c)

	wantStatus(t, f.post("/api/account/recovery", `{"password":"nope"}`, c), 403, "incorrect password")
	if u := f.fileUser("vera"); len(u.RecoveryHashes) != 10 {
		t.Fatal("a wrong password changed the recovery codes")
	} else if _, ok := matchRecoveryCode(u.RecoveryHashes, old[0]); !ok {
		t.Fatal("a wrong password replaced the recovery codes")
	}

	w := f.post("/api/account/recovery", `{"password":"pw"}`, c)
	var r struct {
		Codes []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil || w.Code != 200 || len(r.Codes) != 10 {
		t.Fatalf("regenerate = %d %s, want 10 codes", w.Code, w.Body)
	}
	u := f.fileUser("vera")
	if _, ok := matchRecoveryCode(u.RecoveryHashes, old[0]); ok {
		t.Fatal("an old recovery code still works")
	}
	if _, ok := matchRecoveryCode(u.RecoveryHashes, r.Codes[0]); !ok {
		t.Fatal("a new recovery code doesn't match the stored hashes")
	}
	if e := f.audits("recovery_regenerate"); len(e) != 1 || e[0].Target != "vera" {
		t.Fatalf("audit = %+v, want one recovery_regenerate for vera", e)
	}
}

func TestViewerCannotListUsers(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("vera")
	wantStatus(t, f.do("GET", "/api/users", "", c), 403, "read-only account")
	w := f.do("GET", "/api/users", "", f.signIn("pat"))
	var r struct {
		Users []struct {
			Username     string `json:"username"`
			Role         string `json:"role"`
			TOTP         bool   `json:"totp"`
			RecoveryLeft int    `json:"recovery_left"`
		}
		LoadError string `json:"load_error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil || w.Code != 200 || len(r.Users) != 2 ||
		r.Users[0].Username != "pat" || r.Users[1].Role != "viewer" || r.LoadError != "" {
		t.Fatalf("list = %d %s, want pat and vera and no load_error", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "$2") || strings.Contains(w.Body.String(), "password_hash") {
		t.Fatalf("list leaks credentials: %s", w.Body)
	}
}

func TestEveryAdminRouteRefusesViewers(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("vera")
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/users", ""},
		{"POST", "/api/users", `{"username":"x","role":"viewer","password":"long enough"}`},
		{"POST", "/api/users/role", `{"username":"vera","role":"admin"}`},
		{"POST", "/api/users/password", `{"username":"pat","password":"long enough"}`},
		{"POST", "/api/users/reset-2fa", `{"username":"pat"}`},
		{"POST", "/api/users/remove", `{"username":"pat"}`},
	} {
		wantStatus(t, f.do(tc.method, tc.path, tc.body, c), 403, "read-only account")
	}
	// None of them did anything, and the route table agrees about who may call them.
	if u := f.fileUser("vera"); u.Role != config.RoleViewer {
		t.Fatal("a viewer promoted themselves")
	}
	for _, rt := range f.s.routes() {
		if strings.Contains(rt.pattern, "/api/users") && rt.access != "admin" {
			t.Errorf("%s has access %q, want admin", rt.pattern, rt.access)
		}
		if strings.Contains(rt.pattern, "/api/account/") && rt.access != "self" {
			t.Errorf("%s has access %q, want self", rt.pattern, rt.access)
		}
	}
	if len(f.audits("user_role"))+len(f.audits("user_remove"))+len(f.audits("user_password")) != 0 {
		t.Fatal("refused viewer calls were audited")
	}
}

func TestUsersAddRoleRemove(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("pat")

	if w := f.post("/api/users", `{"username":"carol","role":"viewer","password":"carol's pass"}`, c); w.Code != http.StatusNoContent {
		t.Fatalf("add = %d %s, want 204", w.Code, w.Body)
	}
	if u := f.fileUser("carol"); u.Role != config.RoleViewer || !strings.HasPrefix(u.PasswordHash, "$2") {
		t.Fatalf("carol on disk = %+v", u)
	}
	if w := postLogin(f.h, map[string][]string{"username": {"carol"}, "password": {"carol's pass"}}, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("carol can't sign in with the password she was given: %d", w.Code)
	}

	if w := f.post("/api/users/role", `{"username":"carol","role":"admin"}`, c); w.Code != http.StatusNoContent {
		t.Fatalf("role = %d %s, want 204", w.Code, w.Body)
	}
	if f.fileUser("carol").Role != config.RoleAdmin {
		t.Fatal("carol was not promoted")
	}

	if w := f.post("/api/users/remove", `{"username":"carol"}`, c); w.Code != http.StatusNoContent {
		t.Fatalf("remove = %d %s, want 204", w.Code, w.Body)
	}
	if _, ok := f.s.auth.users.get("carol"); ok {
		t.Fatal("carol is still a user")
	}

	for action, detail := range map[string]string{"user_add": "viewer", "user_role": "viewer → admin", "user_remove": ""} {
		e := f.audits(action)
		if len(e) != 1 || e[0].Target != "carol" || e[0].User != "pat" || e[0].Detail != detail {
			t.Fatalf("%s audit = %+v, want one entry for carol by pat with detail %q", action, e, detail)
		}
	}
}

func TestUsersAddRefusals(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("pat")
	for _, tc := range []struct {
		name, body string
		code       int
		text       string
	}{
		{"duplicate", `{"username":"Vera","role":"viewer","password":"long enough"}`, 409, `duplicate username "Vera"`},
		{"bad name", `{"username":"a b","role":"viewer","password":"long enough"}`, 409, `invalid username "a b"`},
		{"bad role", `{"username":"dan","role":"root","password":"long enough"}`, 409, `unknown role "root"`},
		{"short password", `{"username":"dan","role":"viewer","password":"short"}`, 400, "password must be 8 to 256 characters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantStatus(t, f.post("/api/users", tc.body, c), tc.code, tc.text)
		})
	}
	if len(f.audits("user_add")) != 0 {
		t.Fatal("a refused add was audited")
	}
}

func TestCannotDemoteLastAdmin(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("pat")
	wantStatus(t, f.post("/api/users/role", `{"username":"pat","role":"viewer"}`, c), 409, "at least one admin must remain")
	if f.fileUser("pat").Role != config.RoleAdmin {
		t.Fatal("the last admin was demoted")
	}
	wantStatus(t, f.post("/api/users/role", `{"username":"nobody","role":"viewer"}`, c), 404, "no such user")
}

func TestCannotRemoveSelf(t *testing.T) {
	f := newAcct(t,
		config.AdminUser{Username: "pat", Role: config.RoleAdmin},
		config.AdminUser{Username: "bob", Role: config.RoleAdmin})
	c := f.signIn("pat")
	wantStatus(t, f.post("/api/users/remove", `{"username":"pat"}`, c), 400, "you can't remove your own account")
	wantStatus(t, f.post("/api/users/remove", `{"username":"nobody"}`, c), 404, "no such user")
	if _, ok := f.s.auth.users.get("pat"); !ok {
		t.Fatal("pat removed herself")
	}
}

func TestRemoveEndsTheirSessions(t *testing.T) {
	f := newAcct(t,
		config.AdminUser{Username: "pat", Role: config.RoleAdmin},
		config.AdminUser{Username: "bob", Role: config.RoleAdmin})
	p, b := f.signIn("pat"), f.signIn("bob")
	if w := f.post("/api/users/remove", `{"username":"bob"}`, p); w.Code != 204 {
		t.Fatalf("remove = %d %s", w.Code, w.Body)
	}
	if get(f.h, "/api/health", b).Code != http.StatusUnauthorized {
		t.Fatal("a removed user's session still works")
	}
}

func TestAdminSetsAnotherUsersPassword(t *testing.T) {
	f := twoUsers(t)
	p, v := f.signIn("pat"), f.signIn("vera")
	w := f.post("/api/users/password", `{"username":"vera","password":"set by admin"}`, p)
	if w.Code != http.StatusNoContent {
		t.Fatalf("set password = %d %s, want 204", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			t.Fatal("setting another user's password issued a cookie to the admin")
		}
	}
	if get(f.h, "/api/health", v).Code != http.StatusUnauthorized {
		t.Fatal("vera's old session survived her password being set")
	}
	if get(f.h, "/api/health", p).Code != http.StatusOK {
		t.Fatal("the admin's own session ended")
	}
	if w := postLogin(f.h, map[string][]string{"username": {"vera"}, "password": {"set by admin"}}, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("vera can't sign in with the new password: %d", w.Code)
	}
	if e := f.audits("user_password"); len(e) != 1 || e[0].Target != "vera" {
		t.Fatalf("audit = %+v, want one user_password for vera", e)
	}
	wantStatus(t, f.post("/api/users/password", `{"username":"vera","password":"short"}`, p), 400, "password must be 8 to 256 characters")
	wantStatus(t, f.post("/api/users/password", `{"username":"nobody","password":"long enough"}`, p), 404, "no such user")
}

func TestAdminSetsOwnPasswordKeepsSession(t *testing.T) {
	f := twoUsers(t)
	p := f.signIn("pat")
	w := f.post("/api/users/password", `{"username":"pat","password":"set by myself"}`, p)
	if w.Code != http.StatusNoContent {
		t.Fatalf("set own password = %d %s, want 204", w.Code, w.Body)
	}
	if get(f.h, "/api/health", sessionFrom(t, w)).Code != http.StatusOK {
		t.Fatal("the new cookie was refused")
	}
	if get(f.h, "/api/health", p).Code != http.StatusUnauthorized {
		t.Fatal("the old cookie survived")
	}
}

func TestResetTwoFactor(t *testing.T) {
	f := twoUsers(t)
	p, v := f.signIn("pat"), f.signIn("vera")
	f.enrol(v)
	if w := f.post("/api/users/reset-2fa", `{"username":"vera"}`, p); w.Code != http.StatusNoContent {
		t.Fatalf("reset = %d %s, want 204", w.Code, w.Body)
	}
	if u := f.fileUser("vera"); u.TOTPSecret != "" || u.TOTPLastStep != 0 || len(u.RecoveryHashes) != 0 {
		t.Fatalf("after reset the file holds %+v", u)
	}
	if e := f.audits("user_2fa_reset"); len(e) != 1 || e[0].Target != "vera" {
		t.Fatalf("audit = %+v, want one user_2fa_reset for vera", e)
	}
	wantStatus(t, f.post("/api/users/reset-2fa", `{"username":"nobody"}`, p), 404, "no such user")
}

func TestUsersReportsLoadError(t *testing.T) {
	f := twoUsers(t)
	c := f.signIn("pat")
	f.clock = f.clock.Add(time.Hour)
	f.s.auth.users.now = func() time.Time { return f.clock }
	if err := os.WriteFile(f.file, []byte("users: [this is: not valid"), 0600); err != nil {
		t.Fatal(err)
	}
	w := f.do("GET", "/api/users", "", c)
	var r struct {
		Users     []map[string]any
		LoadError string `json:"load_error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil || w.Code != 200 || r.LoadError == "" || len(r.Users) != 2 {
		t.Fatalf("list = %d %s, want the last good users and a load_error", w.Code, w.Body)
	}
	// A save would overwrite the hand edit, so it is refused.
	wantStatus(t, f.post("/api/users", `{"username":"dan","role":"viewer","password":"long enough"}`, c), 409, "users file is broken")
}
