package admin

// First-run setup: while the users file doesn't exist yet, the console
// serves a one-time link that creates the first admin, so a new install needs
// no shell step. The link's token is random, kept in a 0600 file next to the
// users file (so a restart prints the same link), and removed once an admin
// exists. A users file that exists but is broken never opens setup: that
// stays a lock until someone fixes it.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
)

var errSetupDone = errors.New("an admin already exists")

// SetupURLs returns the links that create the first admin, or none once
// there is one (or no users file is configured for setup).
func (s *Server) SetupURLs() []string {
	tok := s.auth.setupToken()
	if tok == "" {
		return nil
	}
	return SetupLinks(s.listen, tok)
}

// SetupLinks are the setup links for a console listening on listen: one per
// LAN address when it listens on every interface.
func SetupLinks(listen, tok string) []string {
	urls := ConsoleURLs(listen)
	for i := range urls {
		urls[i] += "/setup/" + tok
	}
	return urls
}

// ConsoleURLs are the addresses a console listening on listen can be opened
// at: one per LAN address when it listens on every interface.
func ConsoleURLs(listen string) []string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil
	}
	hosts := []string{host}
	if host == "" || net.ParseIP(host) != nil && net.ParseIP(host).IsUnspecified() {
		if hosts = lanHosts(); len(hosts) == 0 {
			hosts = []string{"<this-server>"}
		}
	}
	urls := make([]string, len(hosts))
	for i, h := range hosts {
		urls[i] = "http://" + net.JoinHostPort(h, port)
	}
	return urls
}

// setupToken returns the setup token, creating its file on first use, or ""
// when setup isn't open. Safe on a nil auth.
func (a *auth) setupToken() string {
	if a == nil || a.setupFile == "" || !a.users.missing() {
		return ""
	}
	a.smu.Lock()
	defer a.smu.Unlock()
	if a.token != "" {
		return a.token
	}
	if b, err := os.ReadFile(a.setupFile); err == nil {
		if t := strings.TrimSpace(string(b)); len(t) == 64 {
			a.token = t
			return t
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("admin: setup token: %v", err)
		return ""
	}
	t := hex.EncodeToString(buf)
	if err := os.WriteFile(a.setupFile, []byte(t+"\n"), 0o600); err != nil {
		// Still usable for this run; the next start prints a new link.
		log.Printf("admin: save setup token: %v", err)
	}
	a.token = t
	return t
}

// setupAllowed reports whether r carries the current setup token. A wrong
// token counts against the sign-in throttle; it answers 404 or 429 itself.
func (a *auth) setupAllowed(w http.ResponseWriter, r *http.Request) bool {
	tok := a.setupToken()
	got := r.PathValue("token")
	if tok != "" && subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1 {
		return true
	}
	if tok != "" && !a.attempts.Allow(clientIP(r)) {
		w.Header().Set("Retry-After", "10")
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return false
	}
	http.NotFound(w, r)
	return false
}

func (a *auth) setupPage(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if a.setupAllowed(w, r) {
		renderLogin(w, http.StatusOK, loginView{Stage: "setup", Token: r.PathValue("token")})
	}
}

func (a *auth) setup(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if !a.setupAllowed(w, r) {
		return
	}
	tok := r.PathValue("token")
	view := func() loginView { return loginView{Stage: "setup", Token: tok, Username: r.PostForm.Get("username")} }
	if !a.loginPost(w, r, view) {
		return
	}
	v := view()
	pw := r.PostForm.Get("password")
	if pw != r.PostForm.Get("confirm") {
		v.Error = "The passwords don't match."
		renderLogin(w, http.StatusBadRequest, v)
		return
	}
	hash, err := config.HashPassword(pw)
	if err != nil {
		v.Error = "The password must be 8 to 256 characters."
		renderLogin(w, http.StatusBadRequest, v)
		return
	}
	u := config.AdminUser{Username: v.Username, PasswordHash: hash, Role: config.RoleAdmin}
	if err := (&config.AdminAuth{Users: []config.AdminUser{u}}).Validate(); err != nil {
		v.Error = "Usernames are 1 to 64 letters, digits and . _ @ -"
		renderLogin(w, http.StatusBadRequest, v)
		return
	}
	switch err := a.users.createFirst(u); {
	case errors.Is(err, errSetupDone):
		http.NotFound(w, r)
		return
	case err != nil:
		log.Printf("admin: setup: %v", err)
		v.Error = "Couldn't save the users file. Loupe's log has the details."
		renderLogin(w, http.StatusInternalServerError, v)
		return
	}
	a.smu.Lock()
	a.token = ""
	if err := os.Remove(a.setupFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("admin: remove setup token: %v", err)
	}
	a.smu.Unlock()
	log.Printf("admin: first admin %q created from %s", u.Username, clientIP(r))
	a.audit.Load().Add(AuditEntry{Time: time.Now(), User: u.Username, IP: clientIP(r), Action: "setup_admin", Target: u.Username})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// missing reports whether the users file doesn't exist and no users are
// loaded, which is when setup is open.
func (s *userStore) missing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.missingLocked()
}

func (s *userStore) missingLocked() bool {
	if s.path == "" || len(s.users) > 0 {
		return false
	}
	_, err := os.Stat(s.path)
	return errors.Is(err, os.ErrNotExist)
}

// createFirst writes a users file holding only u, unless one exists by now.
func (s *userStore) createFirst(u config.AdminUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.missingLocked() {
		return errSetupDone
	}
	if err := config.SaveAdminAuth(s.path, &config.AdminAuth{Users: []config.AdminUser{u}}); err != nil {
		return err
	}
	if st, err := os.Stat(s.path); err == nil {
		s.mtime, s.size = st.ModTime(), st.Size()
	}
	s.users = []config.AdminUser{copyUser(u)}
	s.loadErr, s.logged = "", ""
	return nil
}
