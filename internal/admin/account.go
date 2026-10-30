package admin

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
)

const (
	enrolTTL       = 10 * time.Minute // how long a begun enrolment waits for its code
	maxAccountBody = 4096
)

// enrolment is an authenticator secret shown to a user and not yet confirmed
// with a code. It is kept in memory only, so nothing is stored for a user who
// never finishes.
type enrolment struct {
	secret  []byte
	expires time.Time
}

// beginEnrol starts (or restarts) name's enrolment and returns its new secret.
func (a *auth) beginEnrol(name string) ([]byte, error) {
	secret, err := newTOTPSecret()
	if err != nil {
		return nil, err
	}
	now := a.now()
	a.emu.Lock()
	defer a.emu.Unlock()
	for k, e := range a.enrolling {
		if !now.Before(e.expires) {
			delete(a.enrolling, k)
		}
	}
	a.enrolling[name] = enrolment{secret: secret, expires: now.Add(enrolTTL)}
	return secret, nil
}

// enrolSecret is the secret name has begun enrolling and not let expire.
func (a *auth) enrolSecret(name string) ([]byte, bool) {
	a.emu.Lock()
	defer a.emu.Unlock()
	e, ok := a.enrolling[name]
	if ok && !a.now().Before(e.expires) {
		delete(a.enrolling, name)
		return nil, false
	}
	return e.secret, ok
}

func (a *auth) endEnrol(name string) {
	a.emu.Lock()
	defer a.emu.Unlock()
	delete(a.enrolling, name)
}

// reissue gives the browser that made r a new session for u, whose password
// hash has just changed. The new fingerprint ended every session of u,
// including this one, so without it the user would be signed out by their own
// change. Unlike startSession it answers nothing and records no login.
func (a *auth) reissue(w http.ResponseWriter, r *http.Request, u config.AdminUser) {
	a.revoke(r)
	token, expires, err := a.newSession(clientIP(r), u)
	if err != nil {
		// The change is made; the user just has to sign in again.
		log.Printf("admin: new session after password change: %v", err)
		return
	}
	setCookie(w, r, token, expires)
}

// refusal is an error that says how a handler answers.
type refusal struct {
	code int
	msg  string
}

func (e refusal) Error() string { return e.msg }

var errStale = refusal{http.StatusConflict, "your account changed while this ran, try again"}

// accounts answers 404 and reports false when no users file is configured.
func (s *Server) accounts(w http.ResponseWriter) bool {
	if s.auth == nil {
		http.Error(w, "accounts are off (no admin.auth_file)", http.StatusNotFound)
		return false
	}
	return true
}

// accountRequest is what every account handler starts with: accounts are on,
// the body (if v is not nil) decodes, and the caller is read from the store,
// so a change made since the session was checked is seen.
func (s *Server) accountRequest(w http.ResponseWriter, r *http.Request, v any) (config.AdminUser, bool) {
	if !s.accounts(w) {
		return config.AdminUser{}, false
	}
	if v != nil && !decodeBody(w, r, v) {
		return config.AdminUser{}, false
	}
	su, _ := requestUser(r)
	u, ok := s.auth.users.get(su.Username)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
	return u, ok
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAccountBody)).Decode(v); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

// checkPassword answers 403 unless pw is u's password.
func checkPassword(w http.ResponseWriter, u config.AdminUser, pw string) bool {
	if !config.CheckPassword(u.PasswordHash, pw) {
		http.Error(w, "incorrect password", http.StatusForbidden)
		return false
	}
	return true
}

// hashPassword checks a new password against the length rules and hashes it,
// answering 400 when it is refused.
func hashPassword(w http.ResponseWriter, pw string) (string, bool) {
	h, err := config.HashPassword(pw)
	if errors.Is(err, config.ErrPasswordLength) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return "", false
	}
	if err != nil {
		http.Error(w, "could not hash the password", http.StatusInternalServerError)
		return "", false
	}
	return h, true
}

// change applies fn to the users and answers the failure itself, reporting
// whether it worked. A result that doesn't validate (duplicate or invalid
// name, no admin left) is a 409 with the validation error.
func (s *Server) change(w http.ResponseWriter, fn func(users []config.AdminUser) ([]config.AdminUser, error)) bool {
	err := s.auth.users.update(func(users []config.AdminUser) ([]config.AdminUser, error) {
		next, err := fn(users)
		if err != nil {
			return nil, err
		}
		if err := (&config.AdminAuth{Users: next}).Validate(); err != nil {
			return nil, refusal{http.StatusConflict, err.Error()}
		}
		return next, nil
	})
	var ref refusal
	switch {
	case err == nil:
		return true
	case errors.Is(err, errNoUser):
		http.Error(w, "no such user", http.StatusNotFound)
	case errors.As(err, &ref):
		http.Error(w, ref.msg, ref.code)
	case strings.HasPrefix(err.Error(), "users file is broken"):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		log.Printf("admin: save users: %v", err)
		http.Error(w, "could not save the users file", http.StatusInternalServerError)
	}
	return false
}

// edit applies fn to the user called name. When hash is not empty the change
// is made only if the user still has that password hash, which is the one the
// caller checked a password against.
func (s *Server) edit(w http.ResponseWriter, name, hash string, fn func(u *config.AdminUser) error) bool {
	return s.change(w, func(users []config.AdminUser) ([]config.AdminUser, error) {
		for i := range users {
			if users[i].Username != name {
				continue
			}
			if hash != "" && users[i].PasswordHash != hash {
				return nil, errStale
			}
			return users, fn(&users[i])
		}
		return nil, errNoUser
	})
}

// clear2FA turns two-factor off for u.
func clear2FA(u *config.AdminUser) {
	u.TOTPSecret, u.TOTPLastStep, u.RecoveryHashes = "", 0, nil
}

type userView struct {
	Username     string `json:"username"`
	Role         string `json:"role"`
	TOTP         bool   `json:"totp"`
	RecoveryLeft int    `json:"recovery_left"`
}

func viewOf(u config.AdminUser) userView {
	return userView{u.Username, u.Role, u.TOTPSecret != "", len(u.RecoveryHashes)}
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeJSON(w, struct {
			Auth bool   `json:"auth"`
			Role string `json:"role"`
		}{false, config.RoleAdmin})
		return
	}
	u, ok := s.accountRequest(w, r, nil)
	if !ok {
		return
	}
	v := viewOf(u)
	writeJSON(w, struct {
		User       string `json:"user"`
		Role       string `json:"role"`
		TOTP       bool   `json:"totp"`
		Recovery   int    `json:"recovery_left"`
		Require2FA bool   `json:"require_2fa"`
		Auth       bool   `json:"auth"`
	}{v.Username, v.Role, v.TOTP, v.RecoveryLeft, s.auth.require2FA, true})
}

func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	u, ok := s.accountRequest(w, r, &req)
	if !ok || !checkPassword(w, u, req.Current) {
		return
	}
	hash, ok := hashPassword(w, req.New)
	if !ok {
		return
	}
	if !s.edit(w, u.Username, u.PasswordHash, func(u *config.AdminUser) error {
		u.PasswordHash = hash
		return nil
	}) {
		return
	}
	noteAudit(r, u.Username, "", "")
	if cur, found := s.auth.users.get(u.Username); found {
		s.auth.reissue(w, r, cur)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleEnrolBegin(w http.ResponseWriter, r *http.Request) {
	u, ok := s.accountRequest(w, r, nil)
	if !ok {
		return
	}
	if u.TOTPSecret != "" {
		// Replacing a working authenticator takes the password, so it goes through disable.
		http.Error(w, "two-factor is already on, turn it off first", http.StatusConflict)
		return
	}
	secret, err := s.auth.beginEnrol(u.Username)
	if err != nil {
		http.Error(w, "could not create a secret", http.StatusInternalServerError)
		return
	}
	writeJSON(w, struct {
		Secret string `json:"secret"`
		URI    string `json:"uri"`
	}{encodeTOTPSecret(secret), otpauthURI(u.Username, secret)})
}

func (s *Server) handleEnrolConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	u, ok := s.accountRequest(w, r, &req)
	if !ok {
		return
	}
	secret, ok := s.auth.enrolSecret(u.Username)
	if !ok {
		http.Error(w, "start enrolment again", http.StatusConflict)
		return
	}
	step, ok := checkTOTP(secret, req.Code, s.auth.now(), 0)
	if !ok {
		http.Error(w, "that code didn't work", http.StatusBadRequest)
		return
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		http.Error(w, "could not create recovery codes", http.StatusInternalServerError)
		return
	}
	// One update stores the secret, the accepted step and the recovery hashes,
	// so a sign-in never sees an authenticator without its codes.
	if !s.edit(w, u.Username, "", func(u *config.AdminUser) error {
		if u.TOTPSecret != "" {
			return refusal{http.StatusConflict, "two-factor is already on, turn it off first"}
		}
		u.TOTPSecret, u.TOTPLastStep, u.RecoveryHashes = encodeTOTPSecret(secret), step, hashes
		return nil
	}) {
		return
	}
	s.auth.endEnrol(u.Username)
	noteAudit(r, u.Username, "", "")
	writeJSON(w, struct {
		Codes []string `json:"recovery_codes"`
	}{codes})
}

func (s *Server) handleDisable2FA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	u, ok := s.accountRequest(w, r, &req)
	if !ok || !checkPassword(w, u, req.Password) {
		return
	}
	if s.auth.require2FA {
		http.Error(w, "two-factor is required on this console", http.StatusConflict)
		return
	}
	if u.TOTPSecret == "" {
		http.Error(w, "two-factor is not on", http.StatusConflict)
		return
	}
	if !s.edit(w, u.Username, u.PasswordHash, func(u *config.AdminUser) error {
		clear2FA(u)
		return nil
	}) {
		return
	}
	noteAudit(r, u.Username, "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRecoveryRegenerate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	u, ok := s.accountRequest(w, r, &req)
	if !ok || !checkPassword(w, u, req.Password) {
		return
	}
	if u.TOTPSecret == "" {
		http.Error(w, "two-factor is not on", http.StatusConflict)
		return
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		http.Error(w, "could not create recovery codes", http.StatusInternalServerError)
		return
	}
	if !s.edit(w, u.Username, u.PasswordHash, func(u *config.AdminUser) error {
		if u.TOTPSecret == "" {
			return refusal{http.StatusConflict, "two-factor is not on"}
		}
		u.RecoveryHashes = hashes
		return nil
	}) {
		return
	}
	noteAudit(r, u.Username, "", "")
	writeJSON(w, struct {
		Codes []string `json:"recovery_codes"`
	}{codes})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if !s.accounts(w) {
		return
	}
	users := []userView{}
	for _, u := range s.auth.users.list() {
		users = append(users, viewOf(u))
	}
	writeJSON(w, struct {
		Users     []userView `json:"users"`
		LoadError string     `json:"load_error"`
	}{users, s.auth.users.loadError()})
}

func (s *Server) handleUserAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if !s.accounts(w) || !decodeBody(w, r, &req) {
		return
	}
	hash, ok := hashPassword(w, req.Password)
	if !ok {
		return
	}
	if !s.change(w, func(users []config.AdminUser) ([]config.AdminUser, error) {
		return append(users, config.AdminUser{Username: req.Username, PasswordHash: hash, Role: req.Role}), nil
	}) {
		return
	}
	noteAudit(r, req.Username, req.Role, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUserRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if !s.accounts(w) || !decodeBody(w, r, &req) {
		return
	}
	var was string
	if !s.edit(w, req.Username, "", func(u *config.AdminUser) error {
		was, u.Role = u.Role, req.Role
		return nil
	}) {
		return
	}
	noteAudit(r, req.Username, was+" → "+req.Role, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !s.accounts(w) || !decodeBody(w, r, &req) {
		return
	}
	hash, ok := hashPassword(w, req.Password)
	if !ok {
		return
	}
	if !s.edit(w, req.Username, "", func(u *config.AdminUser) error {
		u.PasswordHash = hash
		return nil
	}) {
		return
	}
	// The new hash ended every session of that user. The caller's own only
	// goes if they changed their own password.
	if me, _ := requestUser(r); me.Username == req.Username {
		if cur, found := s.auth.users.get(req.Username); found {
			s.auth.reissue(w, r, cur)
		}
	}
	noteAudit(r, req.Username, "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUserReset2FA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if !s.accounts(w) || !decodeBody(w, r, &req) {
		return
	}
	if !s.edit(w, req.Username, "", func(u *config.AdminUser) error {
		clear2FA(u)
		return nil
	}) {
		return
	}
	noteAudit(r, req.Username, "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUserRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if !s.accounts(w) || !decodeBody(w, r, &req) {
		return
	}
	if me, _ := requestUser(r); me.Username == req.Username {
		http.Error(w, "you can't remove your own account", http.StatusBadRequest)
		return
	}
	if !s.change(w, func(users []config.AdminUser) ([]config.AdminUser, error) {
		for i := range users {
			if users[i].Username == req.Username {
				return append(users[:i], users[i+1:]...), nil
			}
		}
		return nil, errNoUser
	}) {
		return
	}
	noteAudit(r, req.Username, "", "")
	w.WriteHeader(http.StatusNoContent)
}
