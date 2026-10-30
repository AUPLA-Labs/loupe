package aupldb

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Updater keeps an in-memory DB current: it starts from a local copy and
// polls URL with If-None-Match, so an unchanged file costs a free 304.
// DB() is lock-free, for lookups on every request. Downloads need a token;
// without one (SetToken) it doesn't try. Every file must be signed by one of
// PublicKeys and pass the trust rules in FORMAT.md: never older than the
// current one, not from the future, and dropped once older than MaxAge.
type Updater struct {
	URL      string
	Path     string        // local copy, so a restart doesn't depend on the network
	Interval time.Duration // default 10 minutes
	Client   *http.Client  // default: 2 minute timeout
	Logf     func(format string, args ...any)

	db atomic.Pointer[DB]

	PublicKeys []ed25519.PublicKey // required
	MaxAge     time.Duration       // default 7 days

	now func() time.Time // for tests

	mu           sync.Mutex
	token        string    // sent as "Authorization: Bearer <token>"
	unauthorized bool      // the server refused token
	fetchedAt    time.Time // last 200 or 304
	lastErr      string
	kick         chan struct{}
}

// ErrNoKeys is what Load and Refresh return without PublicKeys.
var ErrNoKeys = errors.New("aupldb: no public keys configured to verify files with")

const (
	defaultMaxAge = 7 * 24 * time.Hour
	maxClockSkew  = time.Hour
)

func (u *Updater) clock() time.Time {
	if u.now != nil {
		return u.now()
	}
	return time.Now()
}

func (u *Updater) maxAge() time.Duration {
	if u.MaxAge > 0 {
		return u.MaxAge
	}
	return defaultMaxAge
}

// accept applies the signature and trust rules to db, a candidate to
// replace cur (nil if there is none).
func (u *Updater) accept(db, cur *DB) error {
	if len(u.PublicKeys) == 0 {
		return ErrNoKeys
	}
	if err := db.Verify(u.PublicKeys); err != nil {
		return err
	}
	now := u.clock()
	switch {
	case db.BuiltAt.After(now.Add(maxClockSkew)):
		return fmt.Errorf("aupldb: file is built in the future (%s)", db.BuiltAt.Format(time.RFC3339))
	case now.Sub(db.BuiltAt) > u.maxAge():
		return fmt.Errorf("aupldb: file is too old (built %s, max age %s)", db.BuiltAt.Format(time.RFC3339), u.maxAge())
	case cur != nil && db.BuiltAt.Before(cur.BuiltAt):
		return fmt.Errorf("aupldb: file is older than the current one (built %s, current %s)",
			db.BuiltAt.Format(time.RFC3339), cur.BuiltAt.Format(time.RFC3339))
	}
	return nil
}

// ErrNoToken is what Refresh returns before a token is set, and
// ErrUnauthorized what it returns when the server refuses the token.
var (
	ErrNoToken      = errors.New("aupldb: no token yet (accept the AUPLA terms in the dashboard)")
	ErrUnauthorized = errors.New("aupldb: token refused")
)

// SetToken replaces the token used from the next request on.
func (u *Updater) SetToken(tok string) {
	u.mu.Lock()
	u.token, u.unauthorized, u.lastErr = tok, false, "" // the old error was about the old token
	u.mu.Unlock()
}

// Token returns the current token, or "".
func (u *Updater) Token() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.token
}

// NeedsToken reports whether there is no token or the server refused it.
func (u *Updater) NeedsToken() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.token == "" || u.unauthorized
}

// MarkUnauthorized records that the server refused the current token, e.g.
// on another endpoint that uses it.
func (u *Updater) MarkUnauthorized() {
	u.mu.Lock()
	u.unauthorized = true
	u.mu.Unlock()
}

// maxDownload bounds what a misbehaving server can make us read.
const maxDownload = 512 << 20

// DB returns the current database, or nil before the first successful
// Load or Refresh and once the current one is older than MaxAge.
func (u *Updater) DB() *DB {
	db := u.db.Load()
	if db == nil || u.clock().Sub(db.BuiltAt) > u.maxAge() {
		return nil
	}
	return db
}

// Load reads the local copy. A missing or corrupt copy is an error, but the
// Updater stays usable: Refresh fetches a fresh one.
func (u *Updater) Load() error {
	db, err := Open(u.Path)
	if err != nil {
		return err
	}
	if err := u.accept(db, u.db.Load()); err != nil {
		return err
	}
	u.db.Store(db)
	return nil
}

// Refresh downloads the file if it changed, validates it completely, saves
// it atomically and only then swaps it in. It reports whether a new file
// was installed; on any error the current DB stays in place.
func (u *Updater) Refresh(ctx context.Context) (bool, error) {
	changed, err := u.refresh(ctx)
	u.mu.Lock()
	if errors.Is(err, ErrUnauthorized) {
		u.unauthorized = true
	}
	if err != nil {
		u.lastErr = err.Error()
	} else {
		u.lastErr, u.fetchedAt = "", time.Now()
	}
	u.mu.Unlock()
	return changed, err
}

func (u *Updater) refresh(ctx context.Context) (bool, error) {
	if u.URL == "" {
		return false, errors.New("aupldb: no download URL configured")
	}
	if len(u.PublicKeys) == 0 {
		return false, ErrNoKeys
	}
	tok := u.Token()
	if tok == "" {
		return false, ErrNoToken
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.URL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	cur := u.db.Load() // even if too old: a 304 still says there is nothing newer
	if cur != nil {
		req.Header.Set("If-None-Match", `"`+cur.SHA256+`"`)
	}
	client := u.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return false, nil
	case http.StatusOK:
	case http.StatusUnauthorized:
		return false, ErrUnauthorized
	default:
		return false, fmt.Errorf("aupldb: %s returned %s", u.URL, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return false, err
	}
	if len(raw) > maxDownload {
		return false, errors.New("aupldb: download too large")
	}
	db, err := Parse(raw)
	if err != nil {
		return false, err
	}
	if err := u.accept(db, cur); err != nil {
		return false, err
	}
	if u.Path != "" {
		if err := writeAtomic(u.Path, raw); err != nil {
			return false, err
		}
	}
	u.db.Store(db)
	return true, nil
}

// Run refreshes every Interval until ctx is done, starting immediately.
func (u *Updater) Run(ctx context.Context) {
	interval := u.Interval
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	logf := u.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		changed, err := u.Refresh(ctx)
		switch {
		case errors.Is(err, ErrNoToken):
			// Waiting for the terms to be accepted; nothing to log.
		case err != nil && ctx.Err() == nil:
			logf("aupldb: refresh failed, keeping current copy: %v", err)
		case changed:
			db := u.db.Load()
			logf("aupldb: installed build of %s (%s)", db.BuiltAt.Format(time.RFC3339), db.SHA256[:16])
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-u.kickC():
		}
	}
}

// Kick makes Run refresh now instead of at the next interval, e.g. right
// after a token was issued.
func (u *Updater) Kick() {
	select {
	case u.kickC() <- struct{}{}:
	default:
	}
}

func (u *Updater) kickC() chan struct{} {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.kick == nil {
		u.kick = make(chan struct{}, 1)
	}
	return u.kick
}

// Status is what the dashboard shows about the database.
type Status struct {
	URL        string    `json:"url"`
	NeedsToken bool      `json:"needs_token"` // the AUPLA terms haven't been accepted, or the token was revoked
	BuiltAt    time.Time `json:"built_at,omitzero"`
	SHA256     string    `json:"sha256,omitempty"`
	FetchedAt  time.Time `json:"fetched_at,omitzero"`
	LastError  string    `json:"last_error,omitempty"`
}

func (u *Updater) Status() Status {
	u.mu.Lock()
	s := Status{URL: u.URL, NeedsToken: u.token == "" || u.unauthorized, FetchedAt: u.fetchedAt, LastError: u.lastErr}
	u.mu.Unlock()
	if db := u.db.Load(); db != nil {
		s.BuiltAt, s.SHA256 = db.BuiltAt, db.SHA256
		if u.DB() == nil && s.LastError == "" {
			s.LastError = fmt.Sprintf("the database is older than %s, so it is not used until a newer build arrives", u.maxAge())
		}
	}
	return s
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".aupldb-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
