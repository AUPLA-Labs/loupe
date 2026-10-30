package admin

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
)

var (
	errNoUser   = errors.New("no such user")
	errCodeUsed = errors.New("code already used")
)

// userReloadEvery is how often get and list look at the users file.
const userReloadEvery = time.Second

// userStore holds the admin users in memory and follows admin_auth.yaml on
// disk, so a hand edit or a CLI command (reset-2fa for a lost phone) takes
// effect while Loupe runs. A file that fails to parse or validate is
// ignored: the last good users stay and loadError reports the problem.
type userStore struct {
	mu        sync.Mutex
	path      string // "" keeps the users in memory only
	users     []config.AdminUser
	mtime     time.Time // of the file as last read or written
	size      int64
	lastCheck time.Time
	loadErr   string
	logged    string // last load error written to the log
	now       func() time.Time
	logf      func(format string, args ...any)
}

func newUserStore(path string, users []config.AdminUser) *userStore {
	s := &userStore{
		path:  path,
		users: copyUsers(users),
		now:   time.Now,
		logf:  log.Printf,
	}
	s.lastCheck = s.now()
	// With no users the file was not loaded (main passes the reason as
	// loadErr). Its mtime and size stay unset, so the next look reads it
	// rather than taking the broken file as already seen.
	if path != "" && len(users) > 0 {
		if st, err := os.Stat(path); err == nil {
			s.mtime, s.size = st.ModTime(), st.Size()
		}
	}
	return s
}

func copyUsers(users []config.AdminUser) []config.AdminUser {
	out := make([]config.AdminUser, len(users))
	for i, u := range users {
		out[i] = copyUser(u)
	}
	return out
}

func copyUser(u config.AdminUser) config.AdminUser {
	u.RecoveryHashes = append([]string(nil), u.RecoveryHashes...)
	return u
}

// get returns the user with exactly this name.
func (s *userStore) get(name string) (config.AdminUser, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload(false)
	for _, u := range s.users {
		if u.Username == name {
			return copyUser(u), true
		}
	}
	return config.AdminUser{}, false
}

// list returns a copy of the users sorted by username.
func (s *userStore) list() []config.AdminUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload(false)
	out := copyUsers(s.users)
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// state returns how many users there are and the load error, if any.
func (s *userStore) state() (users int, loadErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload(false)
	return len(s.users), s.loadErr
}

// loadError is "" when the file last loaded fine.
func (s *userStore) loadError() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload(false)
	return s.loadErr
}

// reload re-reads the file if its mtime or size changed. Unless force is set
// it looks at the file at most once per userReloadEvery. The caller holds mu.
func (s *userStore) reload(force bool) {
	if s.path == "" {
		return
	}
	now := s.now()
	if !force && now.Sub(s.lastCheck) < userReloadEvery {
		return
	}
	s.lastCheck = now
	st, err := os.Stat(s.path)
	if err != nil {
		s.fail(err)
		return
	}
	// Mtimes can be coarse, so a same-second rewrite is told apart by size.
	if st.ModTime().Equal(s.mtime) && st.Size() == s.size {
		return
	}
	s.mtime, s.size = st.ModTime(), st.Size()
	a, err := config.LoadAdminAuth(s.path)
	if err != nil {
		s.fail(err)
		return
	}
	s.users = a.Users
	s.loadErr, s.logged = "", ""
}

// fail records a load error and keeps the current users.
func (s *userStore) fail(err error) {
	s.loadErr = fmt.Sprintf("%s: %v", s.path, err)
	if s.loadErr != s.logged {
		s.logged = s.loadErr
		if len(s.users) == 0 {
			s.logf("admin: users file can't be loaded, sign-in is locked until it is fixed: %s", s.loadErr)
		} else {
			s.logf("admin: users file ignored, keeping the last good users: %s", s.loadErr)
		}
	}
}

// update applies fn to a copy of the current users, which includes any
// change made to the file since the last look. The result is validated and
// saved, then replaces the users. On any error nothing changes. fn's own
// errors and the validation error are returned as they are.
//
// While the file on disk is broken or missing, update refuses: saving would
// overwrite the operator's hand edit with the last good users.
func (s *userStore) update(fn func(users []config.AdminUser) ([]config.AdminUser, error)) error {
	return s.apply(fn, false)
}

// apply is update with a choice for a broken file. With memoryOnlyIfBroken
// the change is kept in memory only, and the file and loadErr stay as they
// are. Sign-in uses that so a code can't be replayed, and the user can still
// get in, while the file waits for a fix.
func (s *userStore) apply(fn func(users []config.AdminUser) ([]config.AdminUser, error), memoryOnlyIfBroken bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reload(true)
	broken := s.loadErr != ""
	if broken && !memoryOnlyIfBroken {
		return errors.New("users file is broken, fix it or run loupe -setup-admin: " + s.loadErr)
	}
	next, err := fn(copyUsers(s.users))
	if err != nil {
		return err
	}
	a := &config.AdminAuth{Users: copyUsers(next)}
	if s.path == "" || broken {
		if err := a.Validate(); err != nil {
			return err
		}
	} else {
		if err := config.SaveAdminAuth(s.path, a); err != nil {
			return err
		}
		if st, err := os.Stat(s.path); err == nil {
			s.mtime, s.size = st.ModTime(), st.Size()
		}
	}
	s.users = a.Users
	return nil
}

// useTOTPStep records step as the user's last accepted TOTP step. It returns
// errCodeUsed unless step is newer than the stored one, so a code can't be
// replayed. The check and the write happen under one lock.
func (s *userStore) useTOTPStep(name string, step int64) error {
	return s.apply(func(users []config.AdminUser) ([]config.AdminUser, error) {
		for i := range users {
			if users[i].Username != name {
				continue
			}
			if step <= users[i].TOTPLastStep {
				return nil, errCodeUsed
			}
			users[i].TOTPLastStep = step
			return users, nil
		}
		return nil, errNoUser
	}, true)
}

// consumeRecovery removes hash from the user's recovery hashes and returns
// how many remain. It returns errCodeUsed if hash isn't there, so a recovery
// code works once.
func (s *userStore) consumeRecovery(name, hash string) (left int, err error) {
	err = s.apply(func(users []config.AdminUser) ([]config.AdminUser, error) {
		for i := range users {
			if users[i].Username != name {
				continue
			}
			for j, h := range users[i].RecoveryHashes {
				if h == hash {
					users[i].RecoveryHashes = append(users[i].RecoveryHashes[:j], users[i].RecoveryHashes[j+1:]...)
					left = len(users[i].RecoveryHashes)
					return users, nil
				}
			}
			return nil, errCodeUsed
		}
		return nil, errNoUser
	}, true)
	return left, err
}
