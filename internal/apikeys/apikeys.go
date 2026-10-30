// Package apikeys holds the API keys Loupe issues for api rules with auth:
// loupe_keys. Keys are stored only as SHA-256 hashes, in a YAML file the
// dashboard writes (0600) and that is re-read when edited by hand.
package apikeys

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/AUPLA-Labs/loupe/internal/ratelimit"
)

// Prefix starts every key, so a leaked one is recognisable in logs and by
// secret scanners.
const Prefix = "lpk_"

// Key is one issued key as stored: everything but the key itself.
type Key struct {
	ID       string     `yaml:"id" json:"id"`
	Name     string     `yaml:"name" json:"name"`
	Hash     string     `yaml:"hash" json:"-"` // SHA-256 hex of the full key
	Created  time.Time  `yaml:"created" json:"created"`
	LastUsed *time.Time `yaml:"last_used,omitempty" json:"last_used,omitempty"`
	CIDRs    []string   `yaml:"cidrs,omitempty" json:"cidrs,omitempty"` // empty = from anywhere
	Rate     float64    `yaml:"rate,omitempty" json:"rate,omitempty"`   // requests per second; 0 = no per-key limit
	Burst    int        `yaml:"burst,omitempty" json:"burst,omitempty"`
}

type file struct {
	Keys []Key `yaml:"keys"`
}

// entry is a Key ready for checking.
type entry struct {
	key      Key
	prefixes []netip.Prefix
	limiter  *ratelimit.Limiter // nil without a rate
}

// Result is what Check made of a presented key.
type Result int

const (
	Unknown   Result = iota // no such key (or none presented)
	Valid                   // known, allowed from this address, within its limit
	WrongNet                // known, but not allowed from this address
	OverLimit               // known, over its own rate limit
)

// Store is the key file in memory. Safe for concurrent use.
type Store struct {
	path string

	mu       sync.Mutex
	byHash   map[string]*entry
	keys     []Key // file order
	modTime  time.Time
	size     int64
	checked  time.Time
	loadErr  string
	used     map[string]time.Time // id → last use not yet written
	now      func() time.Time
	stopOnce sync.Once
	stop     chan struct{}
}

// reloadEvery bounds how often Check looks at the file for a hand edit.
const reloadEvery = 5 * time.Second

// flushEvery is how often last-use times are written: not on every request.
const flushEvery = 5 * time.Minute

// New loads path. A missing file is no keys; a broken one is logged and
// treated as no keys until it is fixed.
func New(path string) *Store {
	s := &Store{path: path, byHash: map[string]*entry{}, used: map[string]time.Time{}, now: time.Now, stop: make(chan struct{})}
	s.mu.Lock()
	s.reloadLocked(true)
	s.mu.Unlock()
	return s
}

// Path is the key file.
func (s *Store) Path() string { return s.path }

// LoadErr is the problem with the file on disk, "" when it loaded.
func (s *Store) LoadErr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadErr
}

// Run writes last-use times every flushEvery until Close.
func (s *Store) Run() {
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.flush()
		case <-s.stop:
			return
		}
	}
}

// Close stops Run and writes pending last-use times.
func (s *Store) Close() {
	s.stopOnce.Do(func() { close(s.stop) })
	s.flush()
}

// Hash is the stored form of a key.
func Hash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// Check looks up a presented key for a client at addr and, when it is valid,
// spends from the key's own limit. id is the key's id when it is known.
func (s *Store) Check(key string, addr netip.Addr) (id string, res Result, retryAfter time.Duration) {
	if !strings.HasPrefix(key, Prefix) || len(key) > 128 {
		return "", Unknown, 0
	}
	h := Hash(key)
	s.mu.Lock()
	if now := s.now(); now.Sub(s.checked) >= reloadEvery {
		s.checked = now
		s.reloadLocked(false)
	}
	e := s.byHash[h]
	s.mu.Unlock()
	if e == nil {
		return "", Unknown, 0
	}
	if len(e.prefixes) > 0 {
		addr = addr.Unmap()
		ok := false
		for _, p := range e.prefixes {
			if p.Contains(addr) {
				ok = true
				break
			}
		}
		if !ok {
			return e.key.ID, WrongNet, 0
		}
	}
	if e.limiter != nil {
		if ok, wait := e.limiter.Take(e.key.ID); !ok {
			return e.key.ID, OverLimit, wait
		}
	}
	s.mu.Lock()
	s.used[e.key.ID] = s.now()
	s.mu.Unlock()
	return e.key.ID, Valid, 0
}

// List returns the keys with their newest last-use times.
func (s *Store) List() []Key {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Key, len(s.keys))
	for i, k := range s.keys {
		if t, ok := s.used[k.ID]; ok {
			k.LastUsed = &t
		}
		k.CIDRs = append([]string(nil), k.CIDRs...)
		out[i] = k
	}
	return out
}

// NewKey describes a key to issue.
type NewKey struct {
	Name  string
	CIDRs []string
	Rate  float64
	Burst int
}

// Create issues a key and returns it in full. This is the only time the key
// itself exists: only its hash is stored.
func (s *Store) Create(n NewKey) (plain string, k Key, err error) {
	n.Name = strings.TrimSpace(n.Name)
	if n.Name == "" || len(n.Name) > 100 {
		return "", Key{}, errors.New("name must be 1 to 100 characters")
	}
	k = Key{Name: n.Name, Rate: n.Rate, Burst: n.Burst, Created: s.now().UTC().Truncate(time.Second)}
	for _, c := range n.CIDRs {
		if c = strings.TrimSpace(c); c != "" {
			k.CIDRs = append(k.CIDRs, c)
		}
	}
	if _, err := compile(k); err != nil {
		return "", Key{}, err
	}
	var secret [32]byte
	rand.Read(secret[:])
	plain = Prefix + base64.RawURLEncoding.EncodeToString(secret[:])
	k.Hash = Hash(plain)
	var idb [6]byte
	rand.Read(idb[:])
	k.ID = "k_" + hex.EncodeToString(idb[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadLocked(false) // build on a hand edit made since
	if s.loadErr != "" {
		return "", Key{}, fmt.Errorf("%s has an error, fix it first: %s", s.path, s.loadErr)
	}
	if err := s.writeLocked(append(append([]Key(nil), s.keys...), k)); err != nil {
		return "", Key{}, err
	}
	return plain, k, nil
}

// Revoke deletes a key. It stops working at once. It reports whether the
// key existed.
func (s *Store) Revoke(id string) (Key, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadLocked(false)
	if s.loadErr != "" {
		return Key{}, false, fmt.Errorf("%s has an error, fix it first: %s", s.path, s.loadErr)
	}
	keys := make([]Key, 0, len(s.keys))
	var gone Key
	found := false
	for _, k := range s.keys {
		if k.ID == id {
			gone, found = k, true
			continue
		}
		keys = append(keys, k)
	}
	if !found {
		return Key{}, false, nil
	}
	delete(s.used, id)
	return gone, true, s.writeLocked(keys)
}

// flush writes pending last-use times.
func (s *Store) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.used) == 0 {
		return
	}
	s.reloadLocked(false)
	if s.loadErr != "" {
		return
	}
	keys := append([]Key(nil), s.keys...)
	for i := range keys {
		if t, ok := s.used[keys[i].ID]; ok {
			t := t.UTC().Truncate(time.Second)
			keys[i].LastUsed = &t
		}
	}
	if err := s.writeLocked(keys); err != nil {
		log.Printf("apikeys: write last use: %v", err)
		return
	}
	clear(s.used)
}

// writeLocked saves keys to the file and applies them.
func (s *Store) writeLocked(keys []Key) error {
	var buf bytes.Buffer
	buf.WriteString("# API keys for api rules with auth: loupe_keys. Only hashes are stored.\n# Managed from the dashboard; hand edits are picked up within seconds.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(file{Keys: keys}); err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, buf.Bytes()); err != nil {
		return err
	}
	if fi, err := os.Stat(s.path); err == nil {
		s.modTime, s.size = fi.ModTime(), fi.Size()
	}
	return s.applyLocked(keys)
}

// reloadLocked re-reads the file when it changed. A broken file keeps the
// keys in force and records the error.
func (s *Store) reloadLocked(force bool) {
	fi, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		if len(s.keys) > 0 || force {
			s.applyLocked(nil)
		}
		s.loadErr, s.modTime, s.size = "", time.Time{}, 0
		return
	}
	if err != nil {
		s.loadErr = err.Error()
		return
	}
	if !force && fi.ModTime().Equal(s.modTime) && fi.Size() == s.size {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		s.loadErr = err.Error()
		return
	}
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && len(bytes.TrimSpace(data)) > 0 {
		s.fail(err)
		return
	}
	if err := s.applyLocked(f.Keys); err != nil {
		s.fail(err)
		return
	}
	s.loadErr, s.modTime, s.size = "", fi.ModTime(), fi.Size()
}

func (s *Store) fail(err error) {
	if s.loadErr != err.Error() {
		log.Printf("apikeys: %s: %v (keeping the keys in force)", s.path, err)
	}
	s.loadErr = err.Error()
}

// applyLocked validates keys and puts them in force, keeping the counters
// of keys whose limit didn't change.
func (s *Store) applyLocked(keys []Key) error {
	by := make(map[string]*entry, len(keys))
	ids := map[string]bool{}
	for i, k := range keys {
		if k.ID == "" || ids[k.ID] {
			return fmt.Errorf("key #%d: missing or duplicate id %q", i+1, k.ID)
		}
		ids[k.ID] = true
		if len(k.Hash) != 64 {
			return fmt.Errorf("key %q: hash must be 64 hex characters", k.ID)
		}
		e, err := compile(k)
		if err != nil {
			return fmt.Errorf("key %q: %w", k.ID, err)
		}
		h := strings.ToLower(k.Hash)
		if old := s.byHash[h]; old != nil && old.limiter != nil && old.key.Rate == k.Rate && old.key.Burst == k.Burst {
			e.limiter = old.limiter
		}
		by[h] = e
	}
	s.byHash, s.keys = by, keys
	return nil
}

func compile(k Key) (*entry, error) {
	e := &entry{key: k}
	for _, c := range k.CIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			a, aerr := netip.ParseAddr(c)
			if aerr != nil {
				return nil, fmt.Errorf("invalid address or CIDR %q", c)
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		} else if p.Masked() != p {
			return nil, fmt.Errorf("%q has host bits set; did you mean %s?", c, p.Masked())
		}
		bits := p.Bits() - unmapBits(p.Addr())
		if bits < 0 {
			return nil, fmt.Errorf("invalid address or CIDR %q", c)
		}
		e.prefixes = append(e.prefixes, netip.PrefixFrom(p.Addr().Unmap(), bits))
	}
	if k.Rate < 0 || k.Rate > 10000 {
		return nil, errors.New("rate must be from 0 to 10000 requests a second")
	}
	if k.Burst < 0 || k.Burst > 100000 {
		return nil, errors.New("burst must be from 0 to 100000")
	}
	if k.Rate > 0 {
		burst := float64(k.Burst)
		if burst < 1 {
			burst = max(1, k.Rate)
		}
		e.limiter = ratelimit.New(k.Rate, burst)
	}
	return e, nil
}

// unmapBits is how many prefix bits a v4-mapped v6 address spends on the
// mapping, so ::ffff:192.0.2.0/120 compares as 192.0.2.0/24.
func unmapBits(a netip.Addr) int {
	if a.Is4In6() {
		return 96
	}
	return 0
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".api_keys-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
