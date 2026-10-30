package handler

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/AUPLA-Labs/loupe/internal/admin"
	"github.com/AUPLA-Labs/loupe/internal/asn"
	"github.com/AUPLA-Labs/loupe/internal/rules"
	"github.com/AUPLA-Labs/loupe/internal/tier"
)

// Rules exposes the rules.yaml manager, for main to keep current.
func (h *Handler) Rules() *rules.Manager { return h.rules }

// ruleResult is what the rule set made of one request: the enforced hit (nil
// when none) and the IDs of the log-only matches. It rides on the request
// context so the events the request ends with can carry it.
type ruleResult struct {
	hit    *rules.Hit
	logged []string
}

type ruleResultKey struct{}

func ruleResultOf(r *http.Request) ruleResult {
	res, _ := r.Context().Value(ruleResultKey{}).(ruleResult)
	return res
}

// rollupPart names the rules behind an event for its rollup key: the
// enforced rule (if any), then the log-only matches.
func (res ruleResult) rollupPart(enforced bool) string {
	logged := strings.Join(res.logged, ",")
	if enforced && res.hit != nil {
		if logged == "" {
			return res.hit.ID
		}
		return res.hit.ID + "|" + logged
	}
	return logged
}

// loggedRules is the rollup-key form of the request's log-only matches.
func loggedRules(r *http.Request) string {
	return ruleResultOf(r).rollupPart(false)
}

// runRules evaluates rules.yaml once for the request and handles the
// outcomes that end it. It returns the request carrying the result, and
// true when it already answered:
//
//   - allow proxies the request, skipping every other check;
//   - block serves the block page, even for public paths and cleared clients;
//   - challenge does nothing here: dispatch raises its tier floor later, so
//     cleared clients, verified bots and allowed networks still pass.
//
// Loopback and private addresses never reach the rules.
func (h *Handler) runRules(w http.ResponseWriter, r *http.Request, ip net.IP) (*http.Request, bool) {
	// No rules (the usual case) must cost nothing: no Facts, no allocation.
	if h.rules == nil || h.rules.Set().Len() == 0 || isPrivateIP(ip) {
		return r, false
	}
	hit, logged := h.rules.Set().Evaluate(h.ruleFacts(r, ip))
	if hit == nil && len(logged) == 0 {
		return r, false
	}
	res := ruleResult{hit: hit, logged: logged}
	r = r.WithContext(context.WithValue(r.Context(), ruleResultKey{}, res))
	if hit == nil {
		return r, false
	}
	key := h.ipKey(r)
	switch hit.Action {
	case rules.ActionAllow:
		// Only page navigations reach the journal: a broad allow rule also
		// matches every asset and API call. The rolled-up event below
		// records the run either way.
		if isDocumentNavigation(r) {
			log.Printf("ALLOW rule=%s ip=%s ua=%q path=%s", hit.ID, ip, r.UserAgent(), r.URL.Path)
		}
		ev := h.newEvent(r, key, 0, "", "ALLOW", "rule_allow", 0)
		ev.Rule = hit.ID
		h.emitRolled(rollupKey{"ALLOW", "rule_allow", key, r.Host, r.UserAgent(), res.rollupPart(true)},
			ev, isDocumentNavigation(r))
		h.proxyThrough(w, r)
		return r, true
	case rules.ActionRateLimit:
		// An API client can't take a challenge, so on an api route an
		// exceeded limit answers 429 whatever its then says.
		if hit.Then != rules.ActionBlock && hit.API == nil {
			return r, false // challenge: dispatch raises the tier, as for a challenge rule
		}
		ev := h.newEvent(r, key, 0, "", "LIMIT", "rule_rate", 0)
		ev.Rule = hit.ID
		h.emitRolled(rollupKey{"LIMIT", "rule_rate", key, r.Host, "", res.rollupPart(true)}, ev, false)
		h.serveRateLimited(w, r, hit.RetryAfter)
		return r, true
	case rules.ActionBlock:
		log.Printf("BLOCK rule=%s ip=%s ua=%q path=%s", hit.ID, ip, r.UserAgent(), r.URL.Path)
		ev := h.newEvent(r, key, 0, "", "BLOCK", "rule_block", 0)
		ev.Rule = hit.ID
		h.emitRolled(rollupKey{"BLOCK", "rule_block", key, r.Host, "", res.rollupPart(true)}, ev, false)
		h.serveBlocked(w, r)
		return r, true
	}
	return r, false
}

// apiPolicyOf is the api rule policy covering the request, nil when no
// enforced api rule matched it.
func apiPolicyOf(r *http.Request) *rules.APIPolicy {
	if hit := ruleResultOf(r).hit; hit != nil {
		return hit.API
	}
	return nil
}

// ruleFloor is the tier a matching challenge rule (or exceeded rate limit
// that challenges) demands, tier.Pass when the request matched none.
func ruleFloor(r *http.Request) tier.Tier {
	if hit := ruleResultOf(r).hit; hit != nil && (hit.Action == rules.ActionChallenge || hit.Action == rules.ActionRateLimit) {
		return hit.Tier
	}
	return tier.Pass
}

// ruleLookups memoises the network lookup behind the ASN, datacenter,
// country and network facts, so a rule set that asks for several costs one
// lookup. ASN 0 is how the database says "not listed" (and how it answers
// before any data is loaded), so it counts as unknown: neither asns nor
// datacenter rules may match it, unless the overlay knows the address.
type ruleLookups struct {
	ip   net.IP
	find func(net.IP) (asn.Record, error)
	done bool
	rec  asn.Record
	ok   bool
}

func (l *ruleLookups) record() (asn.Record, bool) {
	if !l.done {
		l.done = true
		if l.find != nil {
			if rec, err := l.find(l.ip); err == nil {
				l.rec, l.ok = rec, true
			}
		}
	}
	return l.rec, l.ok
}

func (l *ruleLookups) lookup() (uint, bool) {
	rec, ok := l.record()
	return rec.ASN, ok && rec.ASN != 0
}

func (l *ruleLookups) datacenter() (isDatacenter, known bool) {
	rec, ok := l.record()
	if !ok || rec.ASN == 0 && len(rec.Classes) == 0 {
		return false, false
	}
	return rec.Datacenter, true
}

func (l *ruleLookups) country() string {
	rec, _ := l.record()
	return rec.Country
}

func (l *ruleLookups) network() rules.Network {
	rec, _ := l.record()
	return rules.Network{RegisteredCountry: rec.RegisteredCountry, Type: rec.Category, Role: rec.Role, Classes: rec.Classes, List: rec.List}
}

// ruleFacts describes the request for rule evaluation. Everything that costs
// something (the network lookup, the bot DNS check, the clearance cookie
// check) is a function the evaluator calls only if a rule needs it.
func (h *Handler) ruleFacts(r *http.Request, ip net.IP) *rules.Facts {
	l := &ruleLookups{ip: ip}
	if h.asnDB != nil {
		l.find = h.asnDB.Lookup
	}
	clean, anomalies := canonicalPath(r)
	return &rules.Facts{
		Req:        r,
		IP:         ip,
		ClientKey:  h.ipKey(r),
		Path:       clean,
		Anomalies:  anomalies,
		ASN:        l.lookup,
		Datacenter: l.datacenter,
		Country:    l.country,
		Network:    l.network,
		BadIP:      func() int { return h.badIPs.Lists(ip) },
		Bot: func() string {
			if d := h.classifyBot(ip, r.UserAgent()); d.Bot != nil && d.Status() == "verified" {
				return d.Bot.ID
			}
			return ""
		},
		Cleared: func() bool {
			_, valid := h.cookies.Check(r, h.ipKey(r))
			return valid
		},
	}
}

// TestRules evaluates the rule set against r as if it came from ip, without
// answering or proxying anything, for the dashboard's test panel. Facts lists
// what the rules could see; skipped says why no rule ran, if none did.
func (h *Handler) TestRules(r *http.Request, ip net.IP) admin.RulesTest {
	if isPrivateIP(ip) {
		return admin.RulesTest{Skipped: "private address: rules never apply"}
	}
	f := h.ruleFacts(r, ip)
	asn, asnOK := f.ASN()
	dc, dcOK := f.Datacenter()
	facts := map[string]any{
		"bad_ip_lists": f.BadIP(),
		"verified_bot": f.Bot(),
		"cleared":      f.Cleared(),
	}
	if asnOK {
		facts["asn"] = asn
	}
	if dcOK {
		facts["datacenter"] = dc
	}
	if c := f.Country(); c != "" {
		facts["country"] = c
	}
	n := f.Network()
	for k, v := range map[string]string{"registered_country": n.RegisteredCountry, "network_type": n.Type, "network_role": n.Role, "list": n.List} {
		if v != "" {
			facts[k] = v
		}
	}
	if len(n.Classes) > 0 {
		facts["classes"] = n.Classes
	}
	out := admin.RulesTest{Facts: facts}
	if h.rules == nil {
		return out
	}
	hit, logged, counted := h.rules.Set().DryRun(f)
	out.Logged, out.Counted = logged, counted
	if hit != nil {
		out.Hit = &admin.RuleHit{ID: hit.ID, Action: string(hit.Action), API: hit.APIID}
		if hit.Action == rules.ActionChallenge {
			out.Hit.Tier = hit.Tier.String()
		}
	}
	return out
}
