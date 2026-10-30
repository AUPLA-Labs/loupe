package admin

import (
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/badip"

	"github.com/AUPLA-Labs/loupe/internal/asn"
)

// Query selects events from the store. Zero-valued fields match everything.
type Query struct {
	Action  string    // exact action, e.g. "BLOCK"
	IP      string    // exact client key
	ASN     uint      // exact ASN
	Host    string    // exact host
	Reason  string    // exact reason
	Bot     string    // exact bot ID (see Event.Bot)
	BadIP   bool      // only events from addresses on the bad-IP feed
	Country string    // exact country code (where the address is used)
	Class   string    // the address is in this class (tor_exit, vpn, relay, ...)
	Text    string    // case-insensitive substring over ip, path, host, ua, reason, vid, org and signals
	Since   time.Time // inclusive
	Before  time.Time // exclusive; the pagination cursor
	Limit   int       // max events returned; <= 0 means 200, capped at 1000
	All     bool      // ignore Limit and return every match (exports)
}

// ParseQuery reads a Query from URL parameters: action, ip, asn, host,
// reason, bot, badip (any non-empty value), country, class, q, since, before
// (RFC 3339) and limit.
func ParseQuery(v url.Values) Query {
	q := Query{
		Action:  strings.ToUpper(strings.TrimSpace(v.Get("action"))),
		IP:      strings.TrimSpace(v.Get("ip")),
		Host:    strings.TrimSpace(v.Get("host")),
		Reason:  strings.TrimSpace(v.Get("reason")),
		Bot:     strings.TrimSpace(v.Get("bot")),
		BadIP:   strings.TrimSpace(v.Get("badip")) != "",
		Country: strings.ToUpper(strings.TrimSpace(v.Get("country"))),
		Class:   strings.TrimSpace(v.Get("class")),
		Text:    strings.ToLower(strings.TrimSpace(v.Get("q"))),
	}
	if a := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(v.Get("asn"))), "AS"); a != "" {
		if n, err := strconv.ParseUint(a, 10, 32); err == nil {
			q.ASN = uint(n)
		}
	}
	if t, err := time.Parse(time.RFC3339Nano, v.Get("since")); err == nil {
		q.Since = t
	}
	if t, err := time.Parse(time.RFC3339Nano, v.Get("before")); err == nil {
		q.Before = t
	}
	q.Limit, _ = strconv.Atoi(v.Get("limit"))
	return q
}

func (q Query) limit() int {
	switch {
	case q.All:
		return int(^uint(0) >> 1)
	case q.Limit <= 0:
		return 200
	case q.Limit > 1000:
		return 1000
	}
	return q.Limit
}

func (q Query) match(e *Event) bool {
	if q.Action != "" && e.Action != q.Action {
		return false
	}
	if q.IP != "" && e.IP != q.IP {
		return false
	}
	if q.ASN != 0 && e.ASN != q.ASN {
		return false
	}
	if q.Host != "" && e.Host != q.Host {
		return false
	}
	if q.Reason != "" && e.Reason != q.Reason {
		return false
	}
	if q.Bot != "" && e.Bot != q.Bot {
		return false
	}
	if q.BadIP && e.BadIP == 0 {
		return false
	}
	if q.Country != "" && e.Country != q.Country {
		return false
	}
	if q.Class != "" && !slices.Contains(e.Classes, q.Class) {
		return false
	}
	if !q.Since.IsZero() && e.Time.Before(q.Since) {
		return false
	}
	if q.Text != "" && !e.contains(q.Text) {
		return false
	}
	return true
}

// contains reports whether lowered needle occurs in any searchable field.
func (e *Event) contains(needle string) bool {
	for _, f := range [...]string{e.IP, e.Path, e.Host, e.UA, e.Reason, e.VID, e.Org, e.Method, e.Bot, e.Country, e.NetType, e.Provider} {
		if f != "" && strings.Contains(strings.ToLower(f), needle) {
			return true
		}
	}
	if e.ASN != 0 && strings.Contains("as"+strconv.FormatUint(uint64(e.ASN), 10), needle) {
		return true
	}
	for _, sig := range append(e.Reasons, e.Classes...) {
		if strings.Contains(strings.ToLower(sig), needle) {
			return true
		}
	}
	for _, p := range e.Paths {
		if strings.Contains(strings.ToLower(p.Path), needle) {
			return true
		}
	}
	return false
}

// QueryResult is a page of matching events, oldest first. More reports that
// older matches exist beyond this page; pass the first event's time as the
// next Before to fetch them.
type QueryResult struct {
	Events []Event `json:"events"`
	More   bool    `json:"more"`
}

func (s *Store) Query(q Query) QueryResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := q.limit()
	res := QueryResult{Events: make([]Event, 0, min(limit, 64))}
	s.eachNewestLocked(func(e *Event) bool {
		if !q.Before.IsZero() && !e.Time.Before(q.Before) {
			return true
		}
		if !q.Since.IsZero() && e.Time.Before(q.Since) {
			return false
		}
		if !q.match(e) {
			return true
		}
		if len(res.Events) == limit {
			res.More = true
			return false
		}
		res.Events = append(res.Events, *e)
		return true
	})
	for i, j := 0, len(res.Events)-1; i < j; i, j = i+1, j-1 {
		res.Events[i], res.Events[j] = res.Events[j], res.Events[i]
	}
	return res
}

// Activity summarises the buffered events of one client or network.
type Activity struct {
	First    time.Time      `json:"first,omitempty"`
	Last     time.Time      `json:"last,omitempty"`
	Total    int            `json:"total"`
	ByAction map[string]int `json:"by_action"`
	Hosts    []KeyStat      `json:"hosts"`
	Paths    []KeyStat      `json:"paths"`
	UAs      []KeyStat      `json:"uas"`
	Reasons  []KeyStat      `json:"reasons"`
	Signals  []KeyStat      `json:"signals"`
	Events   []Event        `json:"events"` // newest 100, oldest first
}

// activityLocked summarises the events match accepts. each, when set, also
// sees every matching event, newest first.
func (s *Store) activityLocked(match func(e *Event) bool, each func(e *Event)) Activity {
	a := Activity{ByAction: make(map[string]int)}
	hosts, paths, uas, reasons, signals := counter{}, counter{}, counter{}, counter{}, counter{}
	var recent []Event
	s.eachNewestLocked(func(e *Event) bool {
		if !match(e) {
			return true
		}
		if a.Total == 0 {
			a.Last = e.Time
		}
		a.First = e.Time
		n := e.N()
		a.Total += n
		a.ByAction[e.Action] += n
		blocked := e.Action == "BLOCK"
		hosts.add(e.Host, n, blocked)
		paths.addPaths(e, blocked)
		uas.add(e.UA, n, blocked)
		reasons.add(e.Reason, n, blocked)
		for _, sig := range e.Reasons {
			signals.add(sig, 1, blocked)
		}
		if len(recent) < 100 {
			recent = append(recent, *e)
		}
		if each != nil {
			each(e)
		}
		return true
	})
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i]
	}
	a.Events = recent
	if a.Events == nil {
		a.Events = []Event{}
	}
	a.Hosts, a.Paths, a.UAs = hosts.top(8), paths.top(10), uas.top(5)
	a.Reasons, a.Signals = reasons.top(10), signals.top(10)
	return a
}

// IPProfile summarises everything the buffer holds about one client key.
type IPProfile struct {
	IP  string `json:"ip"`
	ASN uint   `json:"asn,omitempty"`
	Org string `json:"org,omitempty"`
	Activity

	// Filled in by the server: what the network database and the published
	// lists say about the address right now.
	Network *asn.Record `json:"network,omitempty"`

	// Filled in by the server from the reputation store.
	Pressure     float64 `json:"pressure"`
	TierFloor    string  `json:"tier_floor"`
	ASNPressure  float64 `json:"asn_pressure,omitempty"`
	ASNTierFloor string  `json:"asn_tier_floor,omitempty"`

	// Filled in from the bad-IP feed: blacklists naming the address now,
	// and what that earns ("none", "challenge", "block").
	BadIP           int          `json:"bad_ip"`
	BadIPAction     badip.Action `json:"-"`
	BadIPActionName string       `json:"bad_ip_action,omitempty"`
}

func (s *Store) Profile(ip string) IPProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p := IPProfile{IP: ip}
	p.Activity = s.activityLocked(func(e *Event) bool { return e.IP == ip }, func(e *Event) {
		if p.ASN == 0 && e.ASN != 0 {
			p.ASN, p.Org = e.ASN, e.Org
		}
	})
	return p
}

// ASNClient is one address seen from a network.
type ASNClient struct {
	IP      string    `json:"ip"`
	Count   int       `json:"count"`
	Blocked int       `json:"blocked"`
	Last    time.Time `json:"last"`

	// Filled in by the server.
	Pressure  float64 `json:"pressure,omitempty"`
	TierFloor string  `json:"tier_floor,omitempty"`
	BadIP     int     `json:"bad_ip,omitempty"`
	BadIPAct  string  `json:"bad_ip_action,omitempty"`
}

// ASNProfile summarises everything the buffer holds about one network.
type ASNProfile struct {
	ASN uint   `json:"asn"`
	Org string `json:"org,omitempty"`
	Activity
	IPCount int         `json:"ip_count"` // distinct addresses
	IPs     []ASNClient `json:"ips"`      // the busiest asnClientMax of them

	// Filled in by the server. TierFloor is the floor the network's
	// pressure enforces, which depends on whether it is a datacenter;
	// Floors are the thresholds that applies.
	Pressure   float64            `json:"pressure"`
	TierFloor  string             `json:"tier_floor"`
	Floors     map[string]float64 `json:"floors"`
	Datacenter bool               `json:"datacenter"`
	Listed     string             `json:"listed,omitempty"` // "blocked" or "allowed" in config.yaml
	Info       *asn.ASNInfo       `json:"info,omitempty"`   // the network's type and registration
	BadIPs     int                `json:"bad_ip_count"`     // externally flagged addresses among IPs
}

const asnClientMax = 200

func (s *Store) ASNProfile(asn uint) ASNProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p := ASNProfile{ASN: asn}
	ips := map[string]*ASNClient{}
	p.Activity = s.activityLocked(func(e *Event) bool { return e.ASN == asn }, func(e *Event) {
		if p.Org == "" {
			p.Org = e.Org
		}
		c, ok := ips[e.IP]
		if !ok {
			c = &ASNClient{IP: e.IP, Last: e.Time}
			ips[e.IP] = c
		}
		c.Count += e.N()
		if e.Action == "BLOCK" {
			c.Blocked += e.N()
		}
	})
	p.IPCount = len(ips)
	p.IPs = make([]ASNClient, 0, len(ips))
	for _, c := range ips {
		p.IPs = append(p.IPs, *c)
	}
	sort.Slice(p.IPs, func(i, j int) bool {
		if p.IPs[i].Count != p.IPs[j].Count {
			return p.IPs[i].Count > p.IPs[j].Count
		}
		return p.IPs[i].IP < p.IPs[j].IP
	})
	if len(p.IPs) > asnClientMax {
		p.IPs = p.IPs[:asnClientMax]
	}
	return p
}
