// Package underattack is the dashboard's under-attack switch: while it is
// on, every new visitor gets at least a chosen challenge, and optionally
// clearances issued before it was turned on must be earned again. It is
// runtime state, not config: it applies at once, survives a restart, and
// can turn itself off at a set time.
package underattack

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

// Tiers a minimum may be set to, by name.
var Tiers = map[string]tier.Tier{
	"lumen_auto":   tier.LumenAuto,
	"single_click": tier.SingleClick,
	"prism":        tier.Prism,
}

// DefaultTier is the minimum when none is chosen.
const DefaultTier = "single_click"

// State is the switch as stored in the file and shown in the dashboard.
type State struct {
	Enabled         bool       `json:"enabled"`
	Since           time.Time  `json:"since,omitzero"`
	Until           *time.Time `json:"until,omitempty"` // nil = until turned off
	MinTier         string     `json:"min_tier,omitempty"`
	RevokeClearance bool       `json:"revoke_clearance,omitempty"`
	By              string     `json:"by,omitempty"`
}

// Active reports whether the state is on at now.
func (s State) Active(now time.Time) bool {
	return s.Enabled && (s.Until == nil || now.Before(*s.Until))
}

// Switch holds the state. Reads are lock-free: they run on every challenge.
type Switch struct {
	path string
	cur  atomic.Pointer[State]
	mu   sync.Mutex // serialises Set
	now  func() time.Time
}

// New loads path. A missing or broken file is off; a broken one is logged.
func New(path string) *Switch {
	u := &Switch{path: path, now: time.Now}
	st := State{}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &st); err != nil {
			log.Printf("underattack: %s: %v (treated as off)", path, err)
			st = State{}
		} else if _, ok := Tiers[st.MinTier]; st.Enabled && !ok {
			st.MinTier = DefaultTier
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Printf("underattack: %v (treated as off)", err)
	}
	u.cur.Store(&st)
	return u
}

// State is the current state, reported off once it has expired.
func (u *Switch) State() State {
	st := *u.cur.Load()
	if st.Enabled && !st.Active(u.now()) {
		st.Enabled = false
	}
	return st
}

// Floor is the minimum tier for a new visitor: tier.Pass when off.
func (u *Switch) Floor() tier.Tier {
	if u == nil {
		return tier.Pass
	}
	st := u.cur.Load()
	if !st.Active(u.now()) {
		return tier.Pass
	}
	return Tiers[st.MinTier]
}

// RevokesIssuedBefore is the time before which clearances no longer count,
// while the switch is on with revoke_clearance.
func (u *Switch) RevokesIssuedBefore() (time.Time, bool) {
	if u == nil {
		return time.Time{}, false
	}
	st := u.cur.Load()
	if !st.RevokeClearance || !st.Active(u.now()) {
		return time.Time{}, false
	}
	return st.Since, true
}

// Set turns the switch on for d (0 = until turned off) or off, and saves it.
func (u *Switch) Set(on bool, d time.Duration, minTier string, revoke bool, by string) (State, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.now().UTC().Truncate(time.Second)
	st := State{}
	if on {
		if minTier == "" {
			minTier = DefaultTier
		}
		if _, ok := Tiers[minTier]; !ok {
			return State{}, fmt.Errorf("unknown tier %q: use lumen_auto, single_click or prism", minTier)
		}
		st = State{Enabled: true, Since: now, MinTier: minTier, RevokeClearance: revoke, By: by}
		// Turning it on again while it is on keeps the original start, so
		// clearances earned since then aren't revoked a second time.
		if prev := u.cur.Load(); prev.Active(now) {
			st.Since = prev.Since
		}
		if d > 0 {
			until := now.Add(d)
			st.Until = &until
		}
	} else {
		st.By = by
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return State{}, err
	}
	if err := writeFileAtomic(u.path, append(data, '\n')); err != nil {
		return State{}, err
	}
	u.cur.Store(&st)
	return st, nil
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".under_attack-*")
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
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
