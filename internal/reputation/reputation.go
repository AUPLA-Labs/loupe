// Package reputation tracks a decaying per-IP and per-ASN "pressure" score
// that raises the challenge tier floor for traffic sources with a history of
// automation, and forgives them automatically as that history ages out.
//
// Pressure decays continuously (computed lazily on read, never on a timer)
// with a configurable half-life, and is halved outright by any clean pass —
// a key that stops behaving like a bot returns to normal on its own, with no
// manual reset and no permanent record.
package reputation

import (
	"log"
	"math"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

// Event names a moment worth recording. Each has a fixed pressure increment
// except CleanPass, which instead halves current pressure outright.
type Event int

const (
	Webdriver Event = iota
	Honeypot
	VerifyFailure
	HighRequestScore
	ChallengeUnanswered
	CleanPass
	// ClearanceAbuse: a clearance cookie was used by a client that
	// contradicts the one it was issued to, or overran its request budget.
	ClearanceAbuse
	// KeyRotation: one device key seen across many IPs/ASNs (proxy
	// rotation), recorded on the device key; or one IP producing many
	// device keys of the same build (anti-detect fingerprint churn),
	// recorded on the IP.
	KeyRotation
	// BuildConclusive: conclusive automation from a browser build, recorded
	// on its build key.
	BuildConclusive
	// BehaviourAnomaly: a cleared client navigated like a script
	// (behaviour.enforce), recorded on the IP.
	BehaviourAnomaly
)

var increments = map[Event]float64{
	Webdriver:           10,
	Honeypot:            10,
	VerifyFailure:       3,
	HighRequestScore:    2,
	ChallengeUnanswered: 1,
	ClearanceAbuse:      3,
	KeyRotation:         5,
	BuildConclusive:     2,
	BehaviourAnomaly:    3,
}

// Floors are the pressure thresholds that raise the challenge tier.
type Floors struct {
	Tier2 float64
	Tier3 float64
	Tier4 float64
}

// Config configures a Store. SnapshotPath, if non-empty, enables disk
// persistence: New restores from it at boot and periodically snapshots to it
// every SnapshotInterval (default 5 minutes) thereafter. Leaving it empty
// disables persistence entirely — the store stays in-memory only.
type Config struct {
	HalfLife                time.Duration
	Floors                  Floors
	NonDatacenterMultiplier float64
	SnapshotPath            string
	SnapshotInterval        time.Duration
}

// entry is one key's pressure state. LastClean is the zero Time until the
// key's first clean pass.
type entry struct {
	Value      float64
	LastUpdate time.Time
	LastClean  time.Time
}

type Store struct {
	mu  sync.Mutex
	ip  map[string]*entry
	asn map[uint]*entry
	// Short-lived client cluster keys. Not
	// snapshotted: the keys themselves rotate every 72 hours, so persisting
	// them would only carry pressure for keys that are about to vanish.
	device map[string]*entry
	build  map[string]*entry
	cfg    Config
}

func New(cfg Config) *Store {
	if cfg.HalfLife <= 0 {
		cfg.HalfLife = 6 * time.Hour
	}
	if cfg.Floors.Tier2 <= 0 {
		cfg.Floors.Tier2 = 4
	}
	if cfg.Floors.Tier3 <= 0 {
		cfg.Floors.Tier3 = 12
	}
	if cfg.Floors.Tier4 <= 0 {
		cfg.Floors.Tier4 = 40
	}
	if cfg.NonDatacenterMultiplier <= 0 {
		cfg.NonDatacenterMultiplier = 4
	}
	s := &Store{
		ip:     make(map[string]*entry),
		asn:    make(map[uint]*entry),
		device: make(map[string]*entry),
		build:  make(map[string]*entry),
		cfg:    cfg,
	}
	if cfg.SnapshotPath != "" {
		if err := s.Restore(cfg.SnapshotPath); err != nil {
			log.Printf("reputation: restore %s: %v", cfg.SnapshotPath, err)
		}
		interval := cfg.SnapshotInterval
		if interval <= 0 {
			interval = 5 * time.Minute
		}
		go s.snapshotLoop(interval)
	}
	go s.evict()
	return s
}

func (s *Store) snapshotLoop(interval time.Duration) {
	for range time.Tick(interval) {
		if err := s.Snapshot(s.cfg.SnapshotPath); err != nil {
			log.Printf("reputation: snapshot %s: %v", s.cfg.SnapshotPath, err)
		}
	}
}

// evict drops entries whose decayed value has fallen below a negligible
// threshold, so a long-lived process does not accumulate an unbounded map
// of one-off IPs that scored a single point months ago and never returned.
// Exponential decay never reaches exactly zero, so a small epsilon stands in
// for "clean."
func (s *Store) evict() {
	const negligible = 0.05
	for range time.Tick(30 * time.Minute) {
		now := time.Now()
		s.mu.Lock()
		for k, e := range s.ip {
			if decay(e.Value, now.Sub(e.LastUpdate), s.cfg.HalfLife) < negligible {
				delete(s.ip, k)
			}
		}
		for a, e := range s.asn {
			if decay(e.Value, now.Sub(e.LastUpdate), s.cfg.HalfLife) < negligible {
				delete(s.asn, a)
			}
		}
		for _, m := range []map[string]*entry{s.device, s.build} {
			for k, e := range m {
				if decay(e.Value, now.Sub(e.LastUpdate), s.cfg.HalfLife) < negligible {
					delete(m, k)
				}
			}
		}
		s.mu.Unlock()
	}
}

// Record applies ev's pressure change to both ipKey and asn (skipping asn
// when it is 0, meaning "unresolved" — recording under that key would
// pollute a meaningless bucket shared by every unresolved lookup).
func (s *Store) Record(ipKey string, asn uint, ev Event) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if ipKey != "" {
		s.apply(s.ipEntryLocked(ipKey), now, ev)
	}
	if asn != 0 {
		s.apply(s.asnEntryLocked(asn), now, ev)
	}
}

// RecordDevice applies ev to a device cluster key; RecordBuild to a build
// cluster key. Empty keys are ignored.
func (s *Store) RecordDevice(deviceKey string, ev Event) { s.recordKeyed(s.device, deviceKey, ev) }
func (s *Store) RecordBuild(buildKey string, ev Event)   { s.recordKeyed(s.build, buildKey, ev) }

func (s *Store) recordKeyed(m map[string]*entry, key string, ev Event) {
	if key == "" {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := m[key]
	if !ok {
		e = &entry{}
		m[key] = e
	}
	s.apply(e, now, ev)
}

// ClientFloor reports the tier floor implied by a client's cluster keys.
// Device pressure applies the base Floors. Build pressure is capped at
// LumenAuto whatever its value: a popular browser build is shared by huge
// numbers of people, so it may only ever cost them an invisible
// proof-of-work, never a click.
func (s *Store) ClientFloor(deviceKey, buildKey string) tier.Tier {
	now := time.Now()
	s.mu.Lock()
	var dv, bv float64
	if deviceKey != "" {
		dv = s.currentValueLocked(s.device[deviceKey], now)
	}
	if buildKey != "" {
		bv = s.currentValueLocked(s.build[buildKey], now)
	}
	s.mu.Unlock()
	buildFloor := floorFor(bv, s.cfg.Floors)
	if buildFloor > tier.LumenAuto {
		buildFloor = tier.LumenAuto
	}
	return tier.Max(floorFor(dv, s.cfg.Floors), buildFloor)
}

// DevicePressure reports deviceKey's current decayed pressure.
func (s *Store) DevicePressure(deviceKey string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentValueLocked(s.device[deviceKey], time.Now())
}

func (s *Store) ipEntryLocked(key string) *entry {
	e, ok := s.ip[key]
	if !ok {
		e = &entry{}
		s.ip[key] = e
	}
	return e
}

func (s *Store) asnEntryLocked(asn uint) *entry {
	e, ok := s.asn[asn]
	if !ok {
		e = &entry{}
		s.asn[asn] = e
	}
	return e
}

func (s *Store) apply(e *entry, now time.Time, ev Event) {
	if !e.LastUpdate.IsZero() {
		e.Value = decay(e.Value, now.Sub(e.LastUpdate), s.cfg.HalfLife)
	}
	if ev == CleanPass {
		e.Value *= 0.5
		e.LastClean = now
	} else {
		e.Value += increments[ev]
	}
	e.LastUpdate = now
}

// decay applies exponential decay: p(now) = p(last) * 0.5^(elapsed/halfLife).
// elapsed is rounded to the nearest second first: decay is meant to model
// hours-scale forgiveness, and without this a Record immediately followed by
// a read (microseconds apart, in the same request) would nudge the value by
// float64 noise from math.Pow, breaking exact-value comparisons for no
// behavioral reason.
func decay(v float64, elapsed, halfLife time.Duration) float64 {
	if v == 0 {
		return 0
	}
	elapsed = elapsed.Round(time.Second)
	if elapsed <= 0 {
		return v
	}
	return v * math.Pow(0.5, elapsed.Hours()/halfLife.Hours())
}

// Floor reports the tier floor implied by current pressure for ipKey and
// asn. IP pressure applies Floors unconditionally. ASN pressure applies the
// same Floors when isDatacenter, and Floors scaled by NonDatacenterMultiplier
// with the result capped at SingleClick otherwise — a handful of infected
// hosts on a residential ASN can never put an innocent customer on Prism.
func (s *Store) Floor(ipKey string, asn uint, isDatacenter bool) tier.Tier {
	now := time.Now()
	s.mu.Lock()
	ipVal := s.currentValueLocked(s.ip[ipKey], now)
	var asnVal float64
	if asn != 0 {
		asnVal = s.currentValueLocked(s.asn[asn], now)
	}
	s.mu.Unlock()

	return tier.Max(floorFor(ipVal, s.cfg.Floors), s.asnFloor(asnVal, isDatacenter))
}

// ASNThresholds returns the floors Floor applies to an ASN's pressure:
// Floors for a datacenter, scaled by NonDatacenterMultiplier otherwise.
func (s *Store) ASNThresholds(isDatacenter bool) Floors {
	if isDatacenter {
		return s.cfg.Floors
	}
	return Floors{
		Tier2: s.cfg.Floors.Tier2 * s.cfg.NonDatacenterMultiplier,
		Tier3: s.cfg.Floors.Tier3 * s.cfg.NonDatacenterMultiplier,
		Tier4: s.cfg.Floors.Tier4 * s.cfg.NonDatacenterMultiplier,
	}
}

// ASNFloorName names the floor an ASN pressure of v enforces, by Floor's rule.
func (s *Store) ASNFloorName(v float64, isDatacenter bool) string {
	return s.asnFloor(v, isDatacenter).String()
}

// asnFloor applies Floor's ASN rule to an ASN pressure value.
func (s *Store) asnFloor(asnVal float64, isDatacenter bool) tier.Tier {
	f := floorFor(asnVal, s.ASNThresholds(isDatacenter))
	if !isDatacenter && f > tier.SingleClick {
		f = tier.SingleClick
	}
	return f
}

// ASNHot reports whether asn's pressure alone puts it over the first
// reputation floor, by the same rule Floor applies to ASNs. Lumen adds a
// single point for it (lumen.Inputs.ASNHot).
func (s *Store) ASNHot(asn uint, isDatacenter bool) bool {
	return s.asnFloor(s.ASNPressure(asn), isDatacenter) >= tier.LumenAuto
}

func floorFor(v float64, f Floors) tier.Tier {
	switch {
	case v >= f.Tier4:
		return tier.Prism
	case v >= f.Tier3:
		return tier.SingleClick
	case v >= f.Tier2:
		return tier.LumenAuto
	default:
		return tier.Pass
	}
}

// Thresholds returns the pressure floors in effect (after defaults), for the
// admin dashboard to draw pressure against.
func (s *Store) Thresholds() Floors { return s.cfg.Floors }

// HalfLife returns the pressure decay half-life in effect.
func (s *Store) HalfLife() time.Duration { return s.cfg.HalfLife }

// FloorName names the tier floor that pressure v maps to, as TopPressured
// reports it.
func (s *Store) FloorName(v float64) string { return floorFor(v, s.cfg.Floors).String() }

// IPPressure reports ipKey's current decayed pressure. Exported for the
// admin dashboard and for tests; not used in the Floor computation itself
// (Floor recomputes it internally under the same lock as the ASN read, so
// the two are read consistently with each other).
func (s *Store) IPPressure(ipKey string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentValueLocked(s.ip[ipKey], time.Now())
}

// ASNPressure reports asn's current decayed pressure. Returns 0 for asn==0.
func (s *Store) ASNPressure(asn uint) float64 {
	if asn == 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentValueLocked(s.asn[asn], time.Now())
}

func (s *Store) currentValueLocked(e *entry, now time.Time) float64 {
	if e == nil {
		return 0
	}
	return decay(e.Value, now.Sub(e.LastUpdate), s.cfg.HalfLife)
}

// PressureEntry is one row of the admin dashboard's "most-pressured keys"
// panel. TierFloor is computed from the base (un-scaled) Floors config for
// both kinds — see the doc comment on TopPressured's caller in
// internal/admin for why ASN rows show a reference value, not the exact
// enforced floor.
type PressureEntry struct {
	Key       string     `json:"key"`
	Kind      string     `json:"kind"` // "ip", "asn", "device" or "build"
	Pressure  float64    `json:"pressure"`
	TierFloor string     `json:"tier_floor"`
	LastClean *time.Time `json:"last_clean,omitempty"`
}

// TopPressured returns up to n keys (IP, ASN, device and build, combined) with positive
// current pressure, sorted by pressure descending.
func (s *Store) TopPressured(n int) []PressureEntry {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []PressureEntry
	for k, e := range s.ip {
		v := s.currentValueLocked(e, now)
		if v <= 0 {
			continue
		}
		out = append(out, PressureEntry{
			Key: k, Kind: "ip", Pressure: v,
			TierFloor: floorFor(v, s.cfg.Floors).String(),
			LastClean: lastCleanPtr(e),
		})
	}
	for a, e := range s.asn {
		v := s.currentValueLocked(e, now)
		if v <= 0 {
			continue
		}
		out = append(out, PressureEntry{
			Key: "AS" + strconv.FormatUint(uint64(a), 10), Kind: "asn", Pressure: v,
			TierFloor: floorFor(v, s.cfg.Floors).String(),
			LastClean: lastCleanPtr(e),
		})
	}
	for kind, m := range map[string]map[string]*entry{"device": s.device, "build": s.build} {
		for k, e := range m {
			v := s.currentValueLocked(e, now)
			if v <= 0 {
				continue
			}
			out = append(out, PressureEntry{
				Key: k, Kind: kind, Pressure: v,
				TierFloor: floorFor(v, s.cfg.Floors).String(),
				LastClean: lastCleanPtr(e),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pressure > out[j].Pressure })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func lastCleanPtr(e *entry) *time.Time {
	if e.LastClean.IsZero() {
		return nil
	}
	t := e.LastClean
	return &t
}
