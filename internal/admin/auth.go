package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/ratelimit"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookie = "loupe_admin"
	sessionTTL    = 7 * 24 * time.Hour
	maxSessions   = 32 // oldest are dropped beyond this, so repeated logins can't grow the file

	pendingTTL   = 5 * time.Minute // how long a correct password waits for its second factor
	maxPending   = 256             // oldest are dropped beyond this, so password logins can't grow the map
	maxCodeTries = 5               // codes tried against one pending sign-in
)

//go:embed login.html
var loginHTML string

var loginTmpl = template.Must(template.New("login").Parse(loginHTML))

// auth guards the admin UI with a login form and a server-side session
// cookie. A nil *auth means no credentials are configured — callers must
// only allow that when the admin listener is loopback-only.
//
// Sessions are kept in a small 0600 file next to the credentials so a
// restart (including the dashboard's own Restart button) doesn't log the
// admin out. Only SHA-256 digests of the tokens are stored, so a leaked
// file can't be replayed, and each session is bound to a fingerprint of
// the password hash of the user it belongs to, so changing that password
// (or `loupe -setup-admin`) or removing the user ends their sessions.
//
// A user with an authenticator gets no session for a correct password alone.
// The password stage leaves a pending sign-in in memory, which the code stage
// turns into a session. It is lost on restart, which costs the user one more
// password entry.
type auth struct {
	users      *userStore
	require2FA bool
	attempts   *ratelimit.Limiter // per IP
	global     *ratelimit.Limiter // across all IPs, against distributed guessing and bcrypt CPU burn
	audit      atomic.Pointer[Audit]
	now        func() time.Time // pending expiry and TOTP steps; a field so tests can move it

	mu       sync.Mutex
	sessions map[string]session // keyed by hex SHA-256 of the cookie token
	path     string             // "" keeps sessions in memory only

	pmu     sync.Mutex
	pending map[string]pendingLogin // keyed by hex SHA-256 of the pending token

	emu       sync.Mutex
	enrolling map[string]enrolment // authenticator secrets not yet confirmed, keyed by username

	setupFile string     // see AuthOptions.SetupTokenFile
	smu       sync.Mutex // guards token
	token     string     // the setup token, once read or made
}

// pendingLogin is a correct password waiting for its second factor.
type pendingLogin struct {
	user    string
	pw      string // fingerprint of the password hash it was checked against
	expires time.Time
	tries   int // codes tried so far, counted before each is checked
}

type session struct {
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	IP       string    `json:"ip"`
	User     string    `json:"user"` // empty in a session saved before users existed; see adopt
	Password string    `json:"pw"`   // fingerprint of the user's password hash at login
}

// AuthOptions says who may sign in to the admin UI and where sessions live.
type AuthOptions struct {
	File         string             // admin_auth.yaml; "" keeps users in memory (tests)
	Users        []config.AdminUser // as loaded at startup; none = no auth (loopback only)
	SessionsPath string
	Require2FA   bool   // enforced when signing in
	LoadError    string // why File failed to load at startup; the store starts from it
	// SetupTokenFile holds the first-run setup token while File doesn't
	// exist; "" = no setup link (see setup.go).
	SetupTokenFile string
}

// newAuth returns nil, meaning no auth, only when there is neither a users
// file nor users. A users file that failed to load gives an auth with no
// users, which refuses every sign-in until the file is fixed: the console
// fails closed, never open.
func newAuth(opts AuthOptions) *auth {
	if opts.File == "" && len(opts.Users) == 0 {
		return nil
	}
	dummyHash() // build it now, so the first unknown-user login isn't the slow one
	users := newUserStore(opts.File, opts.Users)
	if opts.LoadError != "" {
		// main has logged it; the store logs its own reading of the file.
		users.loadErr = opts.LoadError
	}
	a := &auth{
		users:      users,
		require2FA: opts.Require2FA,
		attempts:   ratelimit.New(0.1, 5), // 5 quick tries, then 1 every 10s per IP
		global:     ratelimit.New(1, 20),
		now:        time.Now,
		sessions:   map[string]session{},
		path:       opts.SessionsPath,
		pending:    map[string]pendingLogin{},
		enrolling:  map[string]enrolment{},
		setupFile:  opts.SetupTokenFile,
	}
	a.load()
	return a
}

// fingerprint ties a session to the password hash it was issued under.
func fingerprint(passwordHash string) string {
	sum := sha256.Sum256([]byte(passwordHash))
	return hex.EncodeToString(sum[:8])
}

var (
	dummyOnce sync.Once
	dummy     []byte
)

// dummyFallback is a valid bcrypt hash at DefaultCost of random bytes nobody
// kept. It stands in when the dummy hash can't be built: a nil hash would make
// bcrypt return at once, so an unknown username would answer faster than a
// wrong password and give away which names exist. Nothing can sign in with
// it, since a match only counts for a user that was found.
const dummyFallback = "$2a$10$lV4bQKgIWX80nFPwuvvN9u8NrxsYfrBoI4TG.bYpuchdY7mVugiPK"

// dummyHash is what an unknown username is checked against, so a login for
// a name that doesn't exist costs the same bcrypt run as a wrong password.
func dummyHash() []byte {
	dummyOnce.Do(func() { dummy = buildDummyHash(rand.Reader) })
	return dummy
}

// buildDummyHash hashes random bytes from r at DefaultCost, or returns
// dummyFallback if either step fails.
func buildDummyHash(r io.Reader) []byte {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		log.Printf("admin: build dummy hash: %v; using the built-in one", err)
		return []byte(dummyFallback)
	}
	h, err := bcrypt.GenerateFromPassword(b[:], bcrypt.DefaultCost)
	if err != nil {
		log.Printf("admin: build dummy hash: %v; using the built-in one", err)
		return []byte(dummyFallback)
	}
	return h
}

// adopt names the one user whose password matches a fingerprint. Sessions
// saved before users existed carry no name; this gives them to the single
// admin they were issued to. No match, or more than one, adopts nobody.
func adopt(users []config.AdminUser, fp string) (string, bool) {
	name, n := "", 0
	for _, u := range users {
		if fingerprint(u.PasswordHash) == fp {
			name, n = u.Username, n+1
		}
	}
	return name, n == 1
}

type userKey struct{}

// withUser returns r carrying u as the signed-in user.
func withUser(r *http.Request, u config.AdminUser) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userKey{}, u))
}

// requestUser is the user require let through. ok is false for a request
// that did not pass require, so a missing user never reads as an admin.
func requestUser(r *http.Request) (config.AdminUser, bool) {
	u, ok := r.Context().Value(userKey{}).(config.AdminUser)
	return u, ok
}

type clientIPKey struct{}

// withClientIP records who each request is from, as the resolver set with
// SetClientIP works it out, for clientIP.
func (s *Server) withClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rs := s.client.Load(); rs != nil {
			if ip := rs.Resolve(r).IP; ip.IsValid() {
				r = r.WithContext(context.WithValue(r.Context(), clientIPKey{}, ip.String()))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP is who r is from: as withClientIP resolved it, else the socket.
func clientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey{}).(string); ok {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (a *auth) load() {
	if a.path == "" {
		return
	}
	data, err := os.ReadFile(a.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("admin: read sessions: %v", err)
		}
		return
	}
	var m map[string]session
	if err := json.Unmarshal(data, &m); err != nil {
		log.Printf("admin: sessions file unreadable, starting empty: %v", err)
		return
	}
	users := a.users.list()
	now := time.Now()
	adopted := false
	for k, s := range m {
		if !now.Before(s.Expires) {
			continue
		}
		if s.User == "" {
			name, ok := adopt(users, s.Password)
			if !ok {
				continue
			}
			s.User, adopted = name, true
		}
		if !userMatches(users, s) {
			continue
		}
		a.sessions[k] = s
	}
	if adopted {
		a.mu.Lock()
		a.saveLocked()
		a.mu.Unlock()
	}
}

// userMatches reports whether s's user exists and still has the password
// the session was issued under.
func userMatches(users []config.AdminUser, s session) bool {
	for _, u := range users {
		if u.Username == s.User {
			return fingerprint(u.PasswordHash) == s.Password
		}
	}
	return false
}

// saveLocked persists the session table; a.mu must be held.
func (a *auth) saveLocked() {
	if a.path == "" {
		return
	}
	data, _ := json.Marshal(a.sessions)
	if err := writeFileAtomic(a.path, data, 0600); err != nil {
		log.Printf("admin: save sessions: %v", err)
	}
}

func (a *auth) newSession(ip string, u config.AdminUser) (string, time.Time, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	now := time.Now()
	s := session{Created: now, Expires: now.Add(sessionTTL), IP: ip, User: u.Username, Password: fingerprint(u.PasswordHash)}

	a.mu.Lock()
	defer a.mu.Unlock()
	for k, old := range a.sessions {
		if !now.Before(old.Expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= maxSessions {
		keys := make([]string, 0, len(a.sessions))
		for k := range a.sessions {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return a.sessions[keys[i]].Created.Before(a.sessions[keys[j]].Created) })
		for _, k := range keys[:len(keys)-maxSessions+1] {
			delete(a.sessions, k)
		}
	}
	a.sessions[tokenKey(token)] = s
	a.saveLocked()
	return token, s.Expires, nil
}

// sessionUser returns the user a live session belongs to. A session ends
// when it expires, when its user is gone, or when that user's password no
// longer matches the one it was issued under.
func (a *auth) sessionUser(r *http.Request) (config.AdminUser, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return config.AdminUser{}, false
	}
	k := tokenKey(c.Value)
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[k]
	if !ok {
		return config.AdminUser{}, false
	}
	var u config.AdminUser
	ok = time.Now().Before(s.Expires)
	if ok && s.User == "" {
		var name string
		if name, ok = adopt(a.users.list(), s.Password); ok {
			s.User = name
			a.sessions[k] = s
			a.saveLocked()
		}
	}
	if ok {
		u, ok = a.users.get(s.User)
		ok = ok && fingerprint(u.PasswordHash) == s.Password
	}
	if !ok {
		delete(a.sessions, k)
		a.saveLocked()
		return config.AdminUser{}, false
	}
	return u, true
}

func (a *auth) revoke(r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.sessions[tokenKey(c.Value)]; ok {
		delete(a.sessions, tokenKey(c.Value))
		a.saveLocked()
	}
}

// setCookie issues (or with an empty token, clears) the session cookie.
// Secure is only set when the request itself arrived over TLS, since the
// admin listener is commonly plain HTTP on a LAN or loopback.
func setCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	c := &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	}
	if token == "" {
		c.MaxAge = -1
	} else {
		c.Expires = expires
	}
	http.SetCookie(w, c)
}

// require lets only requests carrying a live session through. Page loads
// are sent to the login form; API calls get a 401 the UI turns into the same.
func (a *auth) require(next http.Handler) http.Handler {
	if a == nil {
		// No credentials, loopback only: everyone is an admin without a name.
		anon := config.AdminUser{Role: config.RoleAdmin}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, withUser(r, anon))
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := a.sessionUser(r); ok {
			next.ServeHTTP(w, withUser(r, u))
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

type loginView struct {
	Username string
	Error    string
	Next     string
	Stage    string // "" asks for the password, "code" for the second factor
	Pending  string // the pending token, on the code stage
	Token    string // the setup token, on the setup stage
}

func renderLogin(w http.ResponseWriter, status int, v loginView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := loginTmpl.Execute(w, v); err != nil {
		log.Printf("admin: render login: %v", err)
	}
}

func (a *auth) loginPage(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if _, ok := a.sessionUser(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if a.setupToken() != "" {
		renderLogin(w, http.StatusOK, loginView{Stage: "nosetup"})
		return
	}
	renderLogin(w, http.StatusOK, loginView{})
}

// nextRe limits the post-login destination to a dashboard route fragment,
// so the login form can't be used as an open redirect.
var nextRe = regexp.MustCompile(`^#/[A-Za-z0-9/_-]{0,64}$`)

// sameOrigin rejects cross-site login posts (login CSRF). Sec-Fetch-Site is
// authoritative where the browser sends it; Origin is only the fallback for
// older browsers, since it can legitimately be "null" on a same-origin form
// post (e.g. under a no-referrer policy) and must not be trusted to match.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
	default:
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

// loginPost runs the checks both sign-in posts share: same origin, a bounded
// body, a parsed form and the attempt limits. It answers the request itself
// when one fails, and reports whether the caller should go on. view is what
// the rate-limit page shows.
func (a *auth) loginPost(w http.ResponseWriter, r *http.Request, view func() loginView) bool {
	if !sameOrigin(r) {
		log.Printf("admin: refused cross-site login from %s (Sec-Fetch-Site=%q Origin=%q Host=%q)",
			clientIP(r), r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Origin"), r.Host)
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	if !a.attempts.Allow(clientIP(r)) || !a.global.Allow("") {
		w.Header().Set("Retry-After", "10")
		v := view()
		v.Error = "Too many attempts. Wait a few seconds and try again."
		renderLogin(w, http.StatusTooManyRequests, v)
		return false
	}
	return true
}

// formNext is the post-login destination the form carried, if it is safe.
func formNext(r *http.Request) string {
	if next := r.PostForm.Get("next"); nextRe.MatchString(next) {
		return next
	}
	return ""
}

func (a *auth) login(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !a.loginPost(w, r, func() loginView {
		return loginView{Username: r.PostForm.Get("username"), Next: formNext(r)}
	}) {
		return
	}
	user, pass := r.PostForm.Get("username"), r.PostForm.Get("password")
	next := formNext(r)
	view := loginView{Username: user, Next: next}
	ip := clientIP(r)

	// Always run bcrypt, even for an unknown username, so timing doesn't
	// reveal which half was wrong.
	u, found := a.users.get(user)
	hash := string(dummyHash())
	if found {
		hash = u.PasswordHash
	}
	passOK := config.CheckPassword(hash, pass)
	if a.setupToken() != "" {
		renderLogin(w, http.StatusServiceUnavailable, loginView{Stage: "nosetup"})
		return
	}
	if n, why := a.users.state(); n == 0 {
		// The users file has never loaded. Say so rather than "incorrect
		// password", but keep the path and parser detail to the log.
		log.Printf("admin: refused login from %s (user=%q): no users loaded: %s", ip, user, why)
		view.Error = "Sign-in is unavailable: the users file can't be loaded. Fix it, or run loupe -setup-admin, and try again."
		renderLogin(w, http.StatusServiceUnavailable, view)
		return
	}
	if !found || !passOK {
		log.Printf("admin: rejected login from %s (user=%q)", ip, user)
		// Rate-limited tries returned above. The rest still arrive at up to
		// the global rate, so Audit coalesces repeats and keeps failures
		// apart from changes. The attempted name is bounded.
		a.audit.Load().Add(AuditEntry{Time: time.Now(), IP: ip, Action: "login_failed", Target: truncateName(user)})
		view.Error = "Incorrect username or password."
		renderLogin(w, http.StatusUnauthorized, view)
		return
	}

	if u.TOTPSecret != "" {
		token, err := a.newPending(u)
		if err != nil {
			http.Error(w, "could not start session", http.StatusInternalServerError)
			return
		}
		renderLogin(w, http.StatusOK, loginView{Stage: "code", Pending: token, Next: next})
		return
	}
	a.startSession(w, r, u, next, "")
}

// startSession ends any session the request carried, issues a new one and
// sends the browser on. A fresh token on every login rules out session
// fixation.
func (a *auth) startSession(w http.ResponseWriter, r *http.Request, u config.AdminUser, next, detail string) {
	ip := clientIP(r)
	a.revoke(r)
	token, expires, err := a.newSession(ip, u)
	if err != nil {
		http.Error(w, "could not start session", http.StatusInternalServerError)
		return
	}
	log.Printf("admin: login from %s", ip)
	a.audit.Load().Add(AuditEntry{Time: time.Now(), User: u.Username, IP: ip, Action: "login", Detail: detail})
	setCookie(w, r, token, expires)
	http.Redirect(w, r, "/"+next, http.StatusSeeOther)
}

// newPending records that u's password was right and returns the token that
// the code stage presents. Only its SHA-256 is kept.
func (a *auth) newPending(u config.AdminUser) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	now := a.now()

	a.pmu.Lock()
	defer a.pmu.Unlock()
	for k, p := range a.pending {
		if !now.Before(p.expires) {
			delete(a.pending, k)
		}
	}
	if len(a.pending) >= maxPending {
		// Every entry lives the same time, so the earliest expiry is the oldest.
		keys := make([]string, 0, len(a.pending))
		for k := range a.pending {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return a.pending[keys[i]].expires.Before(a.pending[keys[j]].expires) })
		for _, k := range keys[:len(keys)-maxPending+1] {
			delete(a.pending, k)
		}
	}
	a.pending[tokenKey(token)] = pendingLogin{user: u.Username, pw: fingerprint(u.PasswordHash), expires: now.Add(pendingTTL)}
	return token, nil
}

// tryPending spends one of the token's code tries and returns its entry. The
// try is counted before the code is checked, so requests racing each other
// can't check more than maxCodeTries codes between them. An unknown or
// expired token, or one with no tries left, is removed and reports false.
func (a *auth) tryPending(token string) (key string, p pendingLogin, ok bool) {
	key = tokenKey(token)
	a.pmu.Lock()
	defer a.pmu.Unlock()
	p, ok = a.pending[key]
	if !ok {
		return key, p, false
	}
	if p.tries++; !a.now().Before(p.expires) || p.tries > maxCodeTries {
		delete(a.pending, key)
		return key, p, false
	}
	a.pending[key] = p
	return key, p, true
}

// takePending removes a pending sign-in and reports whether it was still
// there, so of several requests that each got a code right only one is let in.
func (a *auth) takePending(key string) bool {
	a.pmu.Lock()
	defer a.pmu.Unlock()
	_, ok := a.pending[key]
	delete(a.pending, key)
	return ok
}

// hasLetter reports whether code contains an ASCII letter. Recovery codes do,
// authenticator codes are digits only.
func hasLetter(code string) bool {
	for i := 0; i < len(code); i++ {
		if c := code[i] | 0x20; c >= 'a' && c <= 'z' {
			return true
		}
	}
	return false
}

// secondFactor checks code against u's recovery codes or authenticator and
// spends it. detail is what the audit entry says on success.
func (a *auth) secondFactor(u config.AdminUser, code string) (detail string, ok bool) {
	if hasLetter(code) {
		hash, ok := matchRecoveryCode(u.RecoveryHashes, code)
		if !ok {
			return "", false
		}
		left, err := a.users.consumeRecovery(u.Username, hash)
		if err != nil {
			return "", false
		}
		return fmt.Sprintf("recovery code (%d left)", left), true
	}
	secret, err := decodeTOTPSecret(u.TOTPSecret)
	if err != nil || len(secret) == 0 {
		return "", false
	}
	step, ok := checkTOTP(secret, code, a.now(), u.TOTPLastStep)
	if !ok {
		return "", false
	}
	// The user was read before the code was checked, so a request racing this
	// one may have spent the step already; useTOTPStep decides.
	if err := a.users.useTOTPStep(u.Username, step); err != nil {
		return "", false
	}
	return "authenticator app", true
}

// login2FA is the code stage: it trades a pending sign-in and a valid code
// for a session.
func (a *auth) login2FA(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !a.loginPost(w, r, func() loginView {
		return loginView{Stage: "code", Pending: r.PostForm.Get("pending"), Next: formNext(r)}
	}) {
		return
	}
	next := formNext(r)
	timedOut := func(msg string) {
		renderLogin(w, http.StatusUnauthorized, loginView{Next: next, Error: msg})
	}
	const timedOutMsg = "Your sign-in timed out. Enter your password again."

	token := r.PostForm.Get("pending")
	key, p, ok := a.tryPending(token)
	if !ok {
		timedOut(timedOutMsg)
		return
	}
	// Read the user again: the password may have changed, or the authenticator
	// been reset, since the password stage. An empty secret must end the
	// sign-in here, since the empty key matches a code anyone can compute.
	u, found := a.users.get(p.user)
	if !found || fingerprint(u.PasswordHash) != p.pw || u.TOTPSecret == "" {
		a.takePending(key)
		timedOut(timedOutMsg)
		return
	}

	ip := clientIP(r)
	detail, ok := a.secondFactor(u, r.PostForm.Get("code"))
	if ok {
		if !a.takePending(key) {
			timedOut(timedOutMsg)
			return
		}
		a.startSession(w, r, u, next, detail)
		return
	}

	log.Printf("admin: rejected second factor from %s (user=%q)", ip, u.Username)
	a.audit.Load().Add(AuditEntry{Time: time.Now(), IP: ip, Action: "login_failed", Target: truncateName(u.Username), Detail: "second factor"})
	if p.tries >= maxCodeTries {
		a.takePending(key)
		timedOut("Too many wrong codes. Enter your password again.")
		return
	}
	renderLogin(w, http.StatusUnauthorized, loginView{
		Stage: "code", Pending: token, Next: next,
		Error: "That code didn't work. Try the newest one from your app.",
	})
}

// truncateName bounds an attacker-supplied username for the audit log.
func truncateName(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.ToValidUTF8(s, "")
}

// logout runs behind require and csrfGuard, so only the dashboard itself
// can end a session.
func (a *auth) logout(w http.ResponseWriter, r *http.Request) {
	if a != nil {
		a.revoke(r)
		setCookie(w, r, "", time.Time{})
	}
	w.WriteHeader(http.StatusNoContent)
}

// csrfHeader must accompany every state-changing request. SameSite=Strict
// already keeps the session cookie off cross-site requests; the custom header
// is a second, independent line, since it can't be sent cross-origin without
// a CORS preflight this server never grants.
const csrfHeader = "X-Loupe-Admin"

func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			site := r.Header.Get("Sec-Fetch-Site")
			if r.Header.Get(csrfHeader) == "" || (site != "" && site != "same-origin") {
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders adds baseline hardening headers appropriate for a
// same-origin, fully-inline admin page with no third-party resources.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin, not no-referrer: still nothing leaks to other sites,
		// but the console's own form posts carry a real Origin, not "null".
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
				"font-src 'self' data:; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "+
				"base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}
