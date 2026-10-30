package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/config"
)

// The dashboard's settings form. It covers the settings an operator tunes —
// challenge difficulty, rate limits, score thresholds, reputation, network
// lists — and leaves paths, secrets and listen addresses to config.yaml
// itself (still editable from the dashboard's raw editor). Saving rewrites
// only the changed values in place (config.ApplyEdits), so the file's
// comments and layout survive.

type fieldKind int

const (
	kindInt fieldKind = iota
	kindFloat
	kindASNList
	kindStringList
	kindBool
	kindChoice // one of settingChoices[key]
)

// settingChoices lists the values a kindChoice setting accepts.
var settingChoices = map[string][]string{
	"admin.retention": {"events", "age"},
}

type settingField struct {
	key      string // dotted YAML path
	kind     fieldKind
	min, max float64
	get      func(*config.Config) any
	// note, if set, writes a comment describing the new value, replacing
	// one that would otherwise go stale.
	note func(v float64) string
}

func (f settingField) path() []string { return strings.Split(f.key, ".") }

var settingFields = []settingField{
	{"cookie_ttl", kindInt, 300, 30 * 86400, func(c *config.Config) any { return c.CookieTTL }, func(v float64) string {
		return humanDuration(v) + " (renewal is a silent pulse)"
	}},
	{"lumen.work", kindInt, 1000, 10_000_000, func(c *config.Config) any { return c.Lumen.Work }, lumenWorkNote},
	{"lumen.pulse_work", kindInt, 1000, 10_000_000, func(c *config.Config) any { return c.Lumen.PulseWork }, lumenWorkNote},
	{"lumen.memory_mb", kindInt, 1, 256, func(c *config.Config) any { return c.Lumen.MemoryMB }, nil},
	{"lumen.pulse_memory_mb", kindInt, 1, 256, func(c *config.Config) any { return c.Lumen.PulseMemoryMB }, nil},
	{"lumen.max_memory_mb", kindInt, 1, 256, func(c *config.Config) any { return c.Lumen.MaxMemoryMB }, nil},
	{"lumen.max_level", kindInt, 1, 4, func(c *config.Config) any { return c.Lumen.MaxLevel }, nil},
	{"lumen.enforce", kindBool, 0, 0, func(c *config.Config) any { return c.Lumen.Enforce }, nil},
	{"behaviour.enforce", kindBool, 0, 0, func(c *config.Config) any { return c.Behaviour.Enforce }, nil},
	{"abuse.rate_limit.rate", kindFloat, 0.05, 100, func(c *config.Config) any { return c.Abuse.RateLimit.Rate }, nil},
	{"abuse.rate_limit.burst", kindFloat, 1, 1000, func(c *config.Config) any { return c.Abuse.RateLimit.Burst }, nil},
	{"abuse.clearance_budget.doc_rate", kindFloat, 0.01, 1000, func(c *config.Config) any { return c.Abuse.ClearanceBudget.DocRate }, nil},
	{"abuse.clearance_budget.doc_burst", kindFloat, 10, 100000, func(c *config.Config) any { return c.Abuse.ClearanceBudget.DocBurst }, nil},
	{"abuse.clearance_budget.all_rate", kindFloat, 0.01, 1000, func(c *config.Config) any { return c.Abuse.ClearanceBudget.AllRate }, nil},
	{"abuse.clearance_budget.all_burst", kindFloat, 100, 100000, func(c *config.Config) any { return c.Abuse.ClearanceBudget.AllBurst }, nil},
	{"abuse.fail_threshold", kindInt, 1, 100, func(c *config.Config) any { return c.Abuse.FailThreshold }, nil},
	{"abuse.cooldown_seconds", kindInt, 60, 7 * 86400, func(c *config.Config) any { return c.Abuse.CooldownSeconds }, humanDuration},
	{"hardening.request_score.tier2", kindInt, 1, 100, func(c *config.Config) any { return c.Hardening.RequestScore.Tier2 }, nil},
	{"hardening.request_score.tier3", kindInt, 1, 100, func(c *config.Config) any { return c.Hardening.RequestScore.Tier3 }, nil},
	{"hardening.request_score.tier4", kindInt, 1, 100, func(c *config.Config) any { return c.Hardening.RequestScore.Tier4 }, nil},
	{"reputation.half_life_hours", kindFloat, 0.25, 720, func(c *config.Config) any { return c.Reputation.HalfLifeHours }, nil},
	{"reputation.floors.tier2", kindFloat, 0.5, 10000, func(c *config.Config) any { return c.Reputation.Floors.Tier2 }, nil},
	{"reputation.floors.tier3", kindFloat, 0.5, 10000, func(c *config.Config) any { return c.Reputation.Floors.Tier3 }, nil},
	{"reputation.floors.tier4", kindFloat, 0.5, 10000, func(c *config.Config) any { return c.Reputation.Floors.Tier4 }, nil},
	{"reputation.non_datacenter_multiplier", kindFloat, 1, 100, func(c *config.Config) any { return c.Reputation.NonDatacenterMultiplier }, nil},
	{"bad_ips.enabled", kindBool, 0, 0, func(c *config.Config) any { return c.BadIPs.Enabled }, nil},
	{"bad_ips.challenge_at", kindInt, 1, 50, func(c *config.Config) any { return c.BadIPs.ChallengeAt }, nil},
	{"bad_ips.block_at", kindInt, 0, 50, func(c *config.Config) any { return c.BadIPs.BlockAt }, badIPBlockNote},
	{"admin.retention", kindChoice, 0, 0, func(c *config.Config) any { return c.Admin.Retention }, nil},
	{"admin.capacity", kindInt, 500, 200_000, func(c *config.Config) any { return c.Admin.Capacity }, nil},
	{"admin.max_age_days", kindInt, 1, config.MaxRetentionDays, func(c *config.Config) any { return c.Admin.MaxAgeDays }, func(v float64) string {
		return humanDuration(v * 86400)
	}},
	{"admin.prune_log", kindBool, 0, 0, func(c *config.Config) any { return *c.Admin.PruneLog }, nil},
	{"asn.blocked_asns", kindASNList, 0, 0, func(c *config.Config) any { return c.ASN.BlockedASNs }, nil},
	{"asn.allowed_asns", kindASNList, 0, 0, func(c *config.Config) any { return c.ASN.AllowedASNs }, nil},
	{"asn.datacenter_asns", kindASNList, 0, 0, func(c *config.Config) any { return c.ASN.DatacenterASNs }, nil},
	{"limits.max_url_bytes", kindInt, 1024, 65536, func(c *config.Config) any { return c.Limits.MaxURLBytes }, nil},
	{"limits.max_query_params", kindInt, 16, 10000, func(c *config.Config) any { return c.Limits.MaxQueryParams }, nil},
	{"limits.max_body_bytes", kindInt, 0, 1 << 40, func(c *config.Config) any { return c.Limits.MaxBodyBytes }, bytesNote},
	{"limits.upload_max_body_bytes", kindInt, 0, 1 << 40, func(c *config.Config) any { return c.Limits.UploadMaxBodyBytes }, bytesNote},
	{"limits.allowed_methods", kindStringList, 0, 0, func(c *config.Config) any { return c.Limits.AllowedMethods }, nil},
	{"limits.upload_paths", kindStringList, 0, 0, func(c *config.Config) any { return c.Limits.UploadPaths }, nil},
	{"hardening.exploit_paths", kindStringList, 0, 0, func(c *config.Config) any { return c.Hardening.ExploitPaths }, nil},
	{"bad_bot_uas.patterns", kindStringList, 0, 0, func(c *config.Config) any { return c.BadBotUAs.Patterns }, nil},
}

// bytesNote describes a body limit: "10 MB", or "no limit".
func bytesNote(v float64) string {
	if v == 0 {
		return "no limit"
	}
	return config.RenderFloat(math.Round(v/(1<<20)*100)/100) + " MB"
}

// ASNEntry is a network in one of the ASN lists, labelled with the comment
// next to it in config.yaml or, failing that, an org name seen in traffic.
type ASNEntry struct {
	ASN uint   `json:"asn"`
	Org string `json:"org,omitempty"`
}

type settingsResponse struct {
	ETag   string         `json:"etag"`
	Values map[string]any `json:"values"`
	Error  string         `json:"error,omitempty"`
}

// OrgNames maps ASNs seen in the event buffer to their organisation.
func (s *Store) OrgNames() map[uint]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[uint]string{}
	s.eachNewestLocked(func(e *Event) bool {
		if e.ASN != 0 && e.Org != "" {
			if _, ok := out[e.ASN]; !ok {
				out[e.ASN] = e.Org
			}
		}
		return true
	})
	return out
}

// ASNsWithoutOrg lists the ASNs of buffered events that have no AS name,
// e.g. events logged before the name was looked up.
func (s *Store) ASNsWithoutOrg() []uint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[uint]bool{}
	var out []uint
	s.eachNewestLocked(func(e *Event) bool {
		if e.ASN != 0 && e.Org == "" && !seen[e.ASN] {
			seen[e.ASN] = true
			out = append(out, e.ASN)
		}
		return true
	})
	return out
}

// FillOrg names asn on buffered events that were logged without a name.
// AS names are looked up after the fact (internal/asn's Names), so the
// first events from a new network arrive without one.
func (s *Store) FillOrg(asn uint, org string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eachNewestLocked(func(e *Event) bool {
		if e.ASN == asn && e.Org == "" {
			e.Org = org
		}
		return true
	})
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	src, err := os.ReadFile(s.cfgPath)
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cfg, err := config.LoadBytes(src)
	if err != nil {
		writeJSON(w, settingsResponse{ETag: configETag(src), Error: "config.yaml doesn't load: " + err.Error()})
		return
	}
	orgs := s.store.OrgNames()
	resp := settingsResponse{ETag: configETag(src), Values: map[string]any{}}
	for _, f := range settingFields {
		v := f.get(cfg)
		if f.kind == kindASNList {
			comments := config.ListComments(src, f.path()...)
			list := []ASNEntry{}
			for _, a := range v.([]uint) {
				org := comments[strconv.FormatUint(uint64(a), 10)]
				if org == "" {
					org = orgs[a]
				}
				list = append(list, ASNEntry{ASN: a, Org: org})
			}
			v = list
		}
		if l, ok := v.([]string); ok && l == nil {
			v = []string{}
		}
		resp.Values[f.key] = v
	}
	w.Header().Set("ETag", resp.ETag)
	writeJSON(w, resp)
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ETag   string                     `json:"etag"`
		Values map[string]json.RawMessage `json:"values"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 256*1024)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	src, err := os.ReadFile(s.cfgPath)
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if req.ETag != "" && req.ETag != configETag(src) {
		http.Error(w, "config.yaml changed since this page loaded — reload to see the current settings", http.StatusPreconditionFailed)
		return
	}
	edits, err := settingEdits(req.Values)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if len(edits) == 0 {
		skipAudit(r)
		writeJSON(w, map[string]string{"etag": configETag(src)})
		return
	}
	out, err := config.ApplyEdits(src, edits)
	if err != nil {
		http.Error(w, "couldn't update config.yaml: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	cfg, err := s.validateCandidate(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := checkOrdering(cfg); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := writeFileAtomic(s.cfgPath, out, 0600); err != nil {
		http.Error(w, "write config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	version := s.saveVersion("config", out)
	keys := make([]string, 0, len(edits))
	for _, e := range edits {
		keys = append(keys, strings.Join(e.Path, "."))
	}
	log.Printf("admin: settings saved (%s)", strings.Join(keys, ", "))
	noteAudit(r, "config.yaml", strings.Join(keys, ","), version)
	w.Header().Set("ETag", configETag(out))
	writeJSON(w, map[string]any{"etag": configETag(out), "changed": keys, "saved": time.Now()})
}

// settingEdits validates submitted values and turns them into edits. Unknown
// keys are rejected so a typo can never write something unexpected.
func settingEdits(values map[string]json.RawMessage) ([]config.Edit, error) {
	byKey := map[string]settingField{}
	for _, f := range settingFields {
		byKey[f.key] = f
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var edits []config.Edit
	for _, k := range keys {
		f, ok := byKey[k]
		if !ok {
			return nil, fmt.Errorf("%s can't be changed from the settings form", k)
		}
		raw := values[k]
		e := config.Edit{Path: f.path()}
		switch f.kind {
		case kindInt, kindFloat:
			var v float64
			if err := json.Unmarshal(raw, &v); err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, fmt.Errorf("%s must be a number", k)
			}
			if v < f.min || v > f.max {
				return nil, fmt.Errorf("%s must be between %s and %s", k, config.RenderFloat(f.min), config.RenderFloat(f.max))
			}
			if f.kind == kindInt {
				if v != math.Trunc(v) {
					return nil, fmt.Errorf("%s must be a whole number", k)
				}
				e.Scalar = config.RenderInt(int64(v))
			} else {
				e.Scalar = config.RenderFloat(v)
			}
			if f.note != nil {
				e.Comment = f.note(v)
			}
		case kindBool:
			var v bool
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("%s must be true or false", k)
			}
			e.Scalar = strconv.FormatBool(v)
		case kindChoice:
			var v string
			if err := json.Unmarshal(raw, &v); err != nil || !slices.Contains(settingChoices[k], v) {
				return nil, fmt.Errorf("%s must be one of %s", k, strings.Join(settingChoices[k], ", "))
			}
			e.Scalar = config.RenderString(v)
		case kindASNList:
			var list []ASNEntry
			if err := json.Unmarshal(raw, &list); err != nil {
				return nil, fmt.Errorf("%s must be a list of networks", k)
			}
			e.IsList, e.List = true, []config.ListItem{}
			seen := map[uint]bool{}
			for _, a := range list {
				if a.ASN == 0 || a.ASN > math.MaxUint32 {
					return nil, fmt.Errorf("%s: %d is not a valid ASN", k, a.ASN)
				}
				if seen[a.ASN] {
					continue
				}
				seen[a.ASN] = true
				org := strings.Join(strings.Fields(strings.ReplaceAll(a.Org, "#", "")), " ")
				if len(org) > 80 {
					org = org[:80]
				}
				e.List = append(e.List, config.ListItem{Value: config.RenderInt(int64(a.ASN)), Comment: org})
			}
		case kindStringList:
			var list []string
			if err := json.Unmarshal(raw, &list); err != nil {
				return nil, fmt.Errorf("%s must be a list of text", k)
			}
			e.IsList, e.List = true, []config.ListItem{}
			seen := map[string]bool{}
			for _, s := range list {
				s = strings.TrimSpace(s)
				if s == "" || seen[s] {
					continue
				}
				if len(s) < 3 {
					return nil, fmt.Errorf("%s: %q is too short — it would match far too much", k, s)
				}
				if strings.ContainsAny(s, "\n\r") || len(s) > 200 {
					return nil, fmt.Errorf("%s: %q isn't a valid entry", k, s)
				}
				seen[s] = true
				e.List = append(e.List, config.ListItem{Value: config.RenderString(s)})
			}
		}
		edits = append(edits, e)
	}
	return edits, nil
}

func checkOrdering(c *config.Config) error {
	rs := c.Hardening.RequestScore
	if !(rs.Tier2 < rs.Tier3 && rs.Tier3 < rs.Tier4) {
		return fmt.Errorf("request score thresholds must increase: Lumen (%d) < single-click (%d) < Prism (%d)", rs.Tier2, rs.Tier3, rs.Tier4)
	}
	f := c.Reputation.Floors
	if !(f.Tier2 < f.Tier3 && f.Tier3 < f.Tier4) {
		return fmt.Errorf("reputation floors must increase: Lumen (%g) < single-click (%g) < Prism (%g)", f.Tier2, f.Tier3, f.Tier4)
	}
	if b := c.BadIPs; b.BlockAt != 0 && b.BlockAt < b.ChallengeAt {
		return fmt.Errorf("the bad-IP block threshold (%d lists) can't be below the Prism threshold (%d)", b.BlockAt, b.ChallengeAt)
	}
	l := c.Lumen
	if l.PulseWork > l.Work {
		return fmt.Errorf("the silent check's Lumen work (%d) can't exceed the challenge page's (%d)", l.PulseWork, l.Work)
	}
	if l.PulseMemoryMB > l.MemoryMB {
		return fmt.Errorf("the silent check's Lumen memory (%d MB) can't exceed the challenge page's (%d MB)", l.PulseMemoryMB, l.MemoryMB)
	}
	if l.MemoryMB > l.MaxMemoryMB {
		return fmt.Errorf("Lumen memory (%d MB) can't exceed its ceiling (%d MB)", l.MemoryMB, l.MaxMemoryMB)
	}
	if cb := c.Abuse.ClearanceBudget; cb.AllBurst < cb.DocBurst {
		return fmt.Errorf("the cleared request burst (%g) can't be below the cleared page burst (%g)", cb.AllBurst, cb.DocBurst)
	}
	return nil
}

// lumenWorkNote describes a Standard-level Lumen work value at roughly 2M
// hashes/s on a desktop and 400k on a slow phone, searching all of it.
func lumenWorkNote(v float64) string {
	return fmt.Sprintf("Standard level, worst case: ~%.0fms desktop, ~%.0fms slow mobile, plus memory", v/2000, v/400)
}

func badIPBlockNote(v float64) string {
	if v == 0 {
		return "never block on the list alone"
	}
	return fmt.Sprintf("on %g+ blacklists: 403 instead of Prism; 0 = never", v)
}

// humanDuration renders seconds the way the config's comments do: "15 minutes",
// "24 hours", "7 days".
func humanDuration(sec float64) string {
	unit := func(n float64, name string) string {
		s := strconv.FormatFloat(n, 'f', -1, 64) + " " + name
		if n != 1 {
			s += "s"
		}
		return s
	}
	switch {
	case sec >= 86400 && math.Mod(sec, 86400) == 0:
		return unit(sec/86400, "day")
	case sec >= 3600 && math.Mod(sec, 1800) == 0:
		return unit(sec/3600, "hour")
	case sec >= 60 && math.Mod(sec, 60) == 0:
		return unit(sec/60, "minute")
	}
	return unit(sec, "second")
}
