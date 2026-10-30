package admin

import (
	"sort"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/lumen"
)

// Window is one of the fixed time ranges the dashboard can show. Each pairs
// a span with a bucket width chosen so every range draws 48–84 columns.
type Window struct {
	Name   string
	Span   time.Duration
	Bucket time.Duration
}

var windows = []Window{
	{"1h", time.Hour, time.Minute},
	{"6h", 6 * time.Hour, 5 * time.Minute},
	{"24h", 24 * time.Hour, 30 * time.Minute},
	{"3d", 72 * time.Hour, time.Hour},
	{"7d", 7 * 24 * time.Hour, 2 * time.Hour},
}

// LookupWindow returns the named window, falling back to 24h.
func LookupWindow(name string) Window {
	for _, w := range windows {
		if w.Name == name {
			return w
		}
	}
	return windows[2]
}

type Stats struct {
	Window        string           `json:"window"`
	Start         time.Time        `json:"start"`
	End           time.Time        `json:"end"`
	BucketSeconds int64            `json:"bucket_seconds"`
	Total         int              `json:"total"`
	ByAction      map[string]int   `json:"by_action"`
	PrevTotal     int              `json:"prev_total"`     // the same-length window just before Start
	PrevByAction  map[string]int   `json:"prev_by_action"` // per-action counts for that prior window
	UniqueIPs     int              `json:"unique_ips"`
	PrevUniqueIPs int              `json:"prev_unique_ips"`
	Series        map[string][]int `json:"series"` // action -> per-bucket counts, index 0 = oldest
	TopASNs       []ASNStat        `json:"top_asns"`
	TopIPs        []IPStat         `json:"top_ips"`
	TopReasons    []ReasonStat     `json:"top_reasons"`
	TopSignals    []KeyStat        `json:"top_signals"`
	TopPaths      []KeyStat        `json:"top_paths"`
	TopHosts      []KeyStat        `json:"top_hosts"`
	TopCountries  []KeyStat        `json:"top_countries"` // where the clients' addresses are used
	TopClasses    []KeyStat        `json:"top_classes"`   // tor_exit, vpn, relay, ... from the published lists
	TopNetTypes   []KeyStat        `json:"top_net_types"` // isp, hosting, business, ...
	Buffer        BufferInfo       `json:"buffer"`
	Lumen         LumenStats       `json:"lumen"`
	BadIP         BadIPStats       `json:"bad_ip"`
	Behaviour     BehaviourStats   `json:"behaviour"`
	// Partial is set when the ring buffer's oldest event is newer than the
	// start of the previous window, so deltas compare against incomplete data.
	Partial bool `json:"partial"`
}

// LumenStats breaks the window's challenges down by Lumen level (index =
// int(lumen.Level)), for tuning the level table before enforcing it.
type LumenStats struct {
	Challenged []int `json:"challenged"` // navigations sent to a challenge, by scored level
	Passed     []int `json:"passed"`     // answers that passed, by level
	Answers    []int `json:"answers"`    // answers with a measured solve
	// Medians over those answers: client-reported proof-of-space time, and
	// server-measured hash rate (issue to answer, so network time lowers it).
	SpaceMs []float64 `json:"space_ms"`
	Rate    []float64 `json:"rate"`
}

// BadIPStats is the window's traffic from addresses on the bad-IP feed.
type BadIPStats struct {
	Total     int            `json:"total"`
	ByAction  map[string]int `json:"by_action"`
	ByReason  map[string]int `json:"by_reason"`
	UniqueIPs int            `json:"unique_ips"`
	// ByLists counts distinct listed clients by how many blacklists
	// named them ([n] = on n lists).
	ByLists []int    `json:"by_lists"`
	TopIPs  []IPStat `json:"top_ips"` // busiest listed clients; Lists set
}

// BehaviourStats summarises post-clearance behaviour scoring: cleared
// navigations that scored, by signal and by client, and clearances dropped
// for it (behaviour.enforce).
type BehaviourStats struct {
	Flagged  int            `json:"flagged"`
	Dropped  int            `json:"dropped"`
	BySignal map[string]int `json:"by_signal"`
	TopIPs   []IPStat       `json:"top_ips"` // Count = flagged navigations
}

type ASNStat struct {
	ASN     uint   `json:"asn"`
	Org     string `json:"org"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked"` // BLOCK-action count, for a per-ASN block rate
}

type IPStat struct {
	IP      string    `json:"ip"`
	ASN     uint      `json:"asn,omitempty"`
	Org     string    `json:"org,omitempty"`
	Count   int       `json:"count"`
	Blocked int       `json:"blocked"`
	Last    time.Time `json:"last"`
	Lists   int       `json:"lists,omitempty"` // blacklists naming it (bad-IP feed)
}

type ReasonStat struct {
	Reason      string `json:"reason"`
	Count       int    `json:"count"`
	DominantAct string `json:"dominant_action"`
}

// KeyStat is a generic count for a string key (path, host, signal, UA).
type KeyStat struct {
	Key     string `json:"key"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked"`
}

// counter accumulates KeyStats and returns the top n by count.
type counter map[string]*KeyStat

func (c counter) add(key string, n int, blocked bool) {
	if key == "" {
		return
	}
	k, ok := c[key]
	if !ok {
		k = &KeyStat{Key: key}
		c[key] = k
	}
	k.Count += n
	if blocked {
		k.Blocked += n
	}
}

// addPaths counts e's request paths: each of a summary event's paths with
// its own count, else e.Path once.
func (c counter) addPaths(e *Event, blocked bool) {
	if len(e.Paths) == 0 {
		c.add(e.Path, e.N(), blocked)
		return
	}
	for _, p := range e.Paths {
		c.add(p.Path, p.Count, blocked)
	}
}

func (c counter) top(n int) []KeyStat {
	out := make([]KeyStat, 0, len(c))
	for _, k := range c {
		out = append(out, *k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (s *Store) Stats() Stats { return s.StatsFor(LookupWindow("24h"), time.Now()) }

// StatsFor aggregates the events in w ending at now. Buckets are aligned to
// w.Bucket boundaries, so the last bucket is the current, partial one.
func (s *Store) StatsFor(w Window, now time.Time) Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := int(w.Span / w.Bucket)
	end := now.Truncate(w.Bucket).Add(w.Bucket)
	start := end.Add(-w.Span)
	prevStart := start.Add(-w.Span)

	st := Stats{
		Window:        w.Name,
		Start:         start,
		End:           end,
		BucketSeconds: int64(w.Bucket / time.Second),
		ByAction:      make(map[string]int),
		PrevByAction:  make(map[string]int),
		Series:        make(map[string][]int),
		Buffer:        s.bufferLocked(),
	}
	st.Partial = st.Buffer.Size == st.Buffer.Capacity && st.Buffer.Oldest.After(prevStart)

	asnMap := make(map[uint]*ASNStat)
	ipMap := make(map[string]*IPStat)
	reasonMap := make(map[string]*ReasonStat)
	reasonActs := make(map[string]map[string]int) // reason -> action -> count, to derive DominantAct
	paths, hosts, signals := counter{}, counter{}, counter{}
	countries, classes, netTypes := counter{}, counter{}, counter{}
	prevIPs := make(map[string]struct{})
	levels := int(lumen.MaxLevel) + 1
	st.Lumen = LumenStats{Challenged: make([]int, levels), Passed: make([]int, levels), Answers: make([]int, levels)}
	spaceMs, rates := make([][]float64, levels), make([][]float64, levels)
	st.BadIP = BadIPStats{ByAction: map[string]int{}, ByReason: map[string]int{}, ByLists: []int{}, TopIPs: []IPStat{}}
	st.Behaviour = BehaviourStats{BySignal: map[string]int{}, TopIPs: []IPStat{}}
	behaviourIPs := map[string]*IPStat{}
	badIPs := make(map[string]*IPStat)

	s.eachNewestLocked(func(e *Event) bool {
		switch {
		case !e.Time.Before(end):
			return true
		case !e.Time.Before(start):
			// counted below
		case !e.Time.Before(prevStart):
			st.PrevTotal += e.N()
			st.PrevByAction[e.Action] += e.N()
			prevIPs[e.IP] = struct{}{}
			return true
		default:
			return false // newest-first: everything further is older still
		}

		blocked := e.Action == "BLOCK"
		reqs := e.N()
		st.Total += reqs
		st.ByAction[e.Action] += reqs

		if e.Lumen != nil && *e.Lumen >= 0 && *e.Lumen < levels {
			l := *e.Lumen
			switch {
			case e.LumenDispatch:
				st.Lumen.Challenged[l]++
			case e.LumenRate > 0:
				st.Lumen.Answers[l]++
				rates[l] = append(rates[l], e.LumenRate)
				if e.LumenSpaceMs > 0 {
					spaceMs[l] = append(spaceMs[l], e.LumenSpaceMs)
				}
				if e.Action == "PASS" {
					st.Lumen.Passed[l]++
				}
			}
		}

		series, ok := st.Series[e.Action]
		if !ok {
			series = make([]int, n)
			st.Series[e.Action] = series
		}
		if i := int(e.Time.Sub(start) / w.Bucket); i >= 0 && i < n {
			series[i] += reqs
		}

		if e.ASN != 0 {
			ac, ok := asnMap[e.ASN]
			if !ok {
				ac = &ASNStat{ASN: e.ASN, Org: e.Org}
				asnMap[e.ASN] = ac
			}
			ac.Count += reqs
			if blocked {
				ac.Blocked += reqs
			}
		}

		if e.IP != "" {
			ic, ok := ipMap[e.IP]
			if !ok {
				ic = &IPStat{IP: e.IP, Last: e.Time}
				ipMap[e.IP] = ic
			}
			if ic.ASN == 0 && e.ASN != 0 {
				ic.ASN, ic.Org = e.ASN, e.Org
			}
			ic.Count += reqs
			if blocked {
				ic.Blocked += reqs
			}
		}

		if e.Reason != "" {
			rc, ok := reasonMap[e.Reason]
			if !ok {
				rc = &ReasonStat{Reason: e.Reason}
				reasonMap[e.Reason] = rc
				reasonActs[e.Reason] = make(map[string]int)
			}
			rc.Count += reqs
			reasonActs[e.Reason][e.Action] += reqs
		}

		switch {
		case e.Action == "ALLOW" && e.Reason == "clearance" && e.Score > 0:
			st.Behaviour.Flagged++
			for _, sig := range e.Reasons {
				st.Behaviour.BySignal[sig]++
			}
			bc, ok := behaviourIPs[e.IP]
			if !ok {
				bc = &IPStat{IP: e.IP, ASN: e.ASN, Org: e.Org}
				behaviourIPs[e.IP] = bc
			}
			bc.Count++
			if e.Time.After(bc.Last) {
				bc.Last = e.Time
			}
		case e.Reason == "clearance_behaviour":
			st.Behaviour.Dropped++
		}

		if e.BadIP > 0 {
			st.BadIP.Total += reqs
			st.BadIP.ByAction[e.Action] += reqs
			if e.Reason != "" {
				st.BadIP.ByReason[e.Reason] += reqs
			}
			bc, ok := badIPs[e.IP]
			if !ok {
				bc = &IPStat{IP: e.IP, ASN: e.ASN, Org: e.Org, Last: e.Time, Lists: e.BadIP}
				badIPs[e.IP] = bc
			}
			bc.Count += reqs
			if blocked {
				bc.Blocked += reqs
			}
		}

		paths.addPaths(e, blocked)
		hosts.add(e.Host, reqs, blocked)
		if e.Country != "" {
			countries.add(e.Country, reqs, blocked)
		}
		if e.NetType != "" {
			netTypes.add(e.NetType, reqs, blocked)
		}
		for _, c := range e.Classes {
			classes.add(c, reqs, blocked)
		}
		for _, sig := range e.Reasons {
			signals.add(sig, 1, blocked)
		}
		return true
	})

	st.UniqueIPs = len(ipMap)
	st.PrevUniqueIPs = len(prevIPs)

	for _, ac := range asnMap {
		st.TopASNs = append(st.TopASNs, *ac)
	}
	sort.Slice(st.TopASNs, func(i, j int) bool {
		if st.TopASNs[i].Count != st.TopASNs[j].Count {
			return st.TopASNs[i].Count > st.TopASNs[j].Count
		}
		return st.TopASNs[i].ASN < st.TopASNs[j].ASN
	})
	if len(st.TopASNs) > 10 {
		st.TopASNs = st.TopASNs[:10]
	}

	for _, ic := range ipMap {
		st.TopIPs = append(st.TopIPs, *ic)
	}
	sort.Slice(st.TopIPs, func(i, j int) bool {
		if st.TopIPs[i].Count != st.TopIPs[j].Count {
			return st.TopIPs[i].Count > st.TopIPs[j].Count
		}
		return st.TopIPs[i].IP < st.TopIPs[j].IP
	})
	if len(st.TopIPs) > 10 {
		st.TopIPs = st.TopIPs[:10]
	}

	for reason, rc := range reasonMap {
		best, bestN := "", -1
		for act, n := range reasonActs[reason] {
			if n > bestN || (n == bestN && act < best) {
				best, bestN = act, n
			}
		}
		rc.DominantAct = best
		st.TopReasons = append(st.TopReasons, *rc)
	}
	sort.Slice(st.TopReasons, func(i, j int) bool {
		if st.TopReasons[i].Count != st.TopReasons[j].Count {
			return st.TopReasons[i].Count > st.TopReasons[j].Count
		}
		return st.TopReasons[i].Reason < st.TopReasons[j].Reason
	})
	if len(st.TopReasons) > 10 {
		st.TopReasons = st.TopReasons[:10]
	}

	st.BadIP.UniqueIPs = len(badIPs)
	for _, bc := range badIPs {
		for len(st.BadIP.ByLists) <= bc.Lists {
			st.BadIP.ByLists = append(st.BadIP.ByLists, 0)
		}
		st.BadIP.ByLists[bc.Lists]++
		st.BadIP.TopIPs = append(st.BadIP.TopIPs, *bc)
	}
	sort.Slice(st.BadIP.TopIPs, func(i, j int) bool {
		a, b := st.BadIP.TopIPs[i], st.BadIP.TopIPs[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.IP < b.IP
	})
	if len(st.BadIP.TopIPs) > 8 {
		st.BadIP.TopIPs = st.BadIP.TopIPs[:8]
	}

	for _, bc := range behaviourIPs {
		st.Behaviour.TopIPs = append(st.Behaviour.TopIPs, *bc)
	}
	sort.Slice(st.Behaviour.TopIPs, func(i, j int) bool {
		a, b := st.Behaviour.TopIPs[i], st.Behaviour.TopIPs[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.IP < b.IP
	})
	if len(st.Behaviour.TopIPs) > 5 {
		st.Behaviour.TopIPs = st.Behaviour.TopIPs[:5]
	}

	st.TopPaths = paths.top(10)
	st.TopHosts = hosts.top(10)
	st.TopCountries = countries.top(10)
	st.TopClasses = classes.top(10)
	st.TopNetTypes = netTypes.top(10)
	st.TopSignals = signals.top(10)
	st.Lumen.SpaceMs, st.Lumen.Rate = make([]float64, levels), make([]float64, levels)
	for l := range levels {
		st.Lumen.SpaceMs[l], st.Lumen.Rate[l] = median(spaceMs[l]), median(rates[l])
	}
	return st
}

// BotStat is one bot's traffic over a window, for the dashboard's Bots page.
type BotStat struct {
	Bot      string    `json:"bot"`
	Total    int       `json:"total"`
	Allowed  int       `json:"allowed"`
	Blocked  int       `json:"blocked"`
	Verified int       `json:"verified"`
	Spoofed  int       `json:"spoofed"`
	Last     time.Time `json:"last"`
}

// BotStats counts events tagged with a known bot since the given time.
func (s *Store) BotStats(since time.Time) map[string]*BotStat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]*BotStat{}
	s.eachNewestLocked(func(e *Event) bool {
		if e.Time.Before(since) {
			return false
		}
		if e.Bot == "" {
			return true
		}
		st, ok := out[e.Bot]
		if !ok {
			st = &BotStat{Bot: e.Bot, Last: e.Time}
			out[e.Bot] = st
		}
		st.Total += e.N()
		switch e.Action {
		case "ALLOW":
			st.Allowed += e.N()
		case "BLOCK":
			st.Blocked += e.N()
		}
		switch e.BotStatus {
		case "verified":
			st.Verified++
		case "spoofed":
			st.Spoofed++
		}
		return true
	})
	return out
}

// RuleHits counts the requests each rules.yaml rule matched since the given
// time: enforced for the rule that decided the request, logged for log-only
// matches. Rolled-up events count every request they stand for.
func (s *Store) RuleHits(since time.Time) (enforced, logged map[string]int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	enforced, logged = map[string]int{}, map[string]int{}
	s.eachNewestLocked(func(e *Event) bool {
		if e.Time.Before(since) {
			return false
		}
		if e.Rule != "" {
			enforced[e.Rule] += e.N()
		}
		for _, id := range e.LoggedRules {
			logged[id] += e.N()
		}
		return true
	})
	return enforced, logged
}

// median of v, 0 for none. Sorts v.
func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sort.Float64s(v)
	if n := len(v); n%2 == 0 {
		return (v[n/2-1] + v[n/2]) / 2
	}
	return v[len(v)/2]
}
