package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/rules"
)

// RuleHit is the enforced rule a test request matched.
type RuleHit struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Tier   string `json:"tier,omitempty"` // challenge only
	API    string `json:"api,omitempty"`  // the api rule covering the request, when another rule decided it
}

// RulesTest is what the rule set makes of a request that was never sent.
type RulesTest struct {
	Hit     *RuleHit       `json:"hit"`
	Logged  []string       `json:"logged"`
	Counted []string       `json:"counted,omitempty"` // rate limits the request would count toward
	Facts   map[string]any `json:"facts,omitempty"`
	Skipped string         `json:"skipped,omitempty"`
}

// RulesTestFunc evaluates the live rule set against r from ip, answering and
// proxying nothing.
type RulesTestFunc func(r *http.Request, ip net.IP) RulesTest

// SetRules connects the rules.yaml manager and the request handler's dry run,
// both owned by the handler.
func (s *Server) SetRules(m *rules.Manager, test RulesTestFunc) {
	s.rules.Store(m)
	s.rulesTest.Store(&test)
}

func (s *Server) rulesOr503(w http.ResponseWriter) *rules.Manager {
	m := s.rules.Load()
	if m == nil {
		http.Error(w, "rules are still starting up", http.StatusServiceUnavailable)
	}
	return m
}

// errRulesChanged is a save refused because the file is no longer what the
// editor loaded.
var errRulesChanged = errors.New("rules.yaml changed on disk since it was loaded — reload and reapply your edits")

// ruleErrorJSON is one validation problem, placed so an editor can point at
// the field.
type ruleErrorJSON struct {
	Index int    `json:"index"`
	ID    string `json:"id,omitempty"`
	Field string `json:"field,omitempty"`
	Msg   string `json:"msg"`
}

// writeRulesError answers a refused save: 412 for a stale ETag, 422 with the
// validation problems as a list, 500 for anything else.
func writeRulesError(w http.ResponseWriter, err error) {
	if errors.Is(err, errRulesChanged) {
		http.Error(w, err.Error(), http.StatusPreconditionFailed)
		return
	}
	var list []ruleErrorJSON
	errs := []error{err}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		errs = j.Unwrap()
	}
	for _, e := range errs {
		var re *rules.RuleError
		if !errors.As(e, &re) {
			list = nil
			break
		}
		list = append(list, ruleErrorJSON{Index: re.Index, ID: re.ID, Field: re.Field, Msg: re.Msg})
	}
	if list == nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "errors": list}) //nolint:errcheck
}

func (s *Server) handleRulesGet(w http.ResponseWriter, r *http.Request) {
	m := s.rulesOr503(w)
	if m == nil {
		return
	}
	current, ok := readCurrent(w, m.Path())
	if !ok {
		return
	}
	enforced, logged := s.store.RuleHits(time.Now().Add(-24 * time.Hour))
	rs := m.Rules()
	if rs == nil {
		rs = []rules.Rule{}
	}
	w.Header().Set("ETag", configETag(current))
	writeJSON(w, map[string]any{
		"rules":   rs,
		"loadErr": m.LoadErr(),
		"etag":    configETag(current),
		"hits":    enforced,
		"logged":  logged,
	})
}

// saveRules writes rs if the file still has the bytes etag fingerprints ("" =
// don't check). The bytes it replaces are kept as a version first, so a save
// over a hand edit (even a broken one) can be undone; when that fails nothing
// is saved.
func (s *Server) saveRules(r *http.Request, m *rules.Manager, rs []rules.Rule, etag, detail string) (version string, after []byte, err error) {
	before, after, err := m.SaveIf(rs, func(cur []byte) error {
		if etag != "" && etag != configETag(cur) {
			return errRulesChanged
		}
		if len(cur) > 0 {
			if _, err := s.history.Load().Save("rules", cur); err != nil {
				return fmt.Errorf("couldn't save the current rules.yaml to the history, so nothing was saved: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	version = s.saveVersion("rules", after)
	if detail == "" {
		detail = diffDetail(before, after)
	}
	noteAudit(r, "rules.yaml", detail, version)
	return version, after, nil
}

func (s *Server) handleRulesSave(w http.ResponseWriter, r *http.Request) {
	m := s.rulesOr503(w)
	if m == nil {
		return
	}
	var req struct {
		Rules []rules.Rule `json:"rules"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad rules: "+err.Error(), http.StatusBadRequest)
		return
	}
	version, after, err := s.saveRules(r, m, req.Rules, r.Header.Get("If-Match"), "")
	if err != nil {
		writeRulesError(w, err)
		return
	}
	log.Printf("admin: rules saved (%d rules)", len(m.Rules()))
	w.Header().Set("ETag", configETag(after))
	writeJSON(w, map[string]any{"etag": configETag(after), "version": version})
}

// handleRulesTest runs the rules against a described request. The url may be
// a full URL or a path; with a path the host comes from a Host header.
func (s *Server) handleRulesTest(w http.ResponseWriter, r *http.Request) {
	f := s.rulesTest.Load()
	if f == nil {
		http.Error(w, "rules are still starting up", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		IP      string            `json:"ip"`
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	ip := net.ParseIP(strings.TrimSpace(req.IP))
	if ip == nil {
		http.Error(w, "ip must be an IP address", http.StatusBadRequest)
		return
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	u, err := url.Parse(strings.TrimSpace(req.URL))
	if err != nil || (u.Path == "" && u.Host == "") {
		http.Error(w, "url must be a URL or a path", http.StatusBadRequest)
		return
	}
	if u.Path == "" {
		u.Path = "/"
	}
	tr := &http.Request{Method: method, URL: &url.URL{Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}, Header: http.Header{}, Host: u.Host, RemoteAddr: net.JoinHostPort(ip.String(), "0")}
	for k, v := range req.Headers {
		if strings.EqualFold(k, "Host") {
			if tr.Host == "" {
				tr.Host = v
			}
			continue
		}
		tr.Header.Set(k, v)
	}
	// The dry run must judge the address it was given, not one a header claims.
	tr.Header.Del("CF-Connecting-IP")
	tr.Header.Del("X-Forwarded-For")
	tr = tr.WithContext(r.Context())
	writeJSON(w, (*f)(tr, ip))
}

// quickBlockDurations are the lengths a quick block may have.
var quickBlockDurations = map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}

// handleQuickBlock puts an enforced, expiring block rule for one address or
// range at the top of rules.yaml, above any allow rule, so it wins.
func (s *Server) handleQuickBlock(w http.ResponseWriter, r *http.Request) {
	m := s.rulesOr503(w)
	if m == nil {
		return
	}
	var req struct {
		IP       string `json:"ip"`
		Duration string `json:"duration"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	target := strings.TrimSpace(req.IP)
	d, ok := quickBlockDurations[req.Duration]
	if !ok {
		http.Error(w, `duration must be "1h", "24h" or "7d"`, http.StatusBadRequest)
		return
	}
	var addr netip.Addr
	if p, err := netip.ParsePrefix(target); err == nil {
		addr = p.Addr()
	} else if a, err := netip.ParseAddr(target); err == nil {
		addr = a
	} else {
		http.Error(w, "ip must be an address or a CIDR range", http.StatusBadRequest)
		return
	}
	addr = addr.Unmap()
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsUnspecified() {
		http.Error(w, "private and loopback addresses never reach the rules, so there is nothing to block", http.StatusUnprocessableEntity)
		return
	}
	// Build on the file as it is, not the live set, which can lag a hand
	// edit by a few seconds; the save then refuses if it changed meanwhile.
	current, ok := readCurrent(w, m.Path())
	if !ok {
		return
	}
	existing, err := rules.Parse(current)
	if err != nil {
		http.Error(w, "rules.yaml has an error, fix it first: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(d)
	on := true
	rule := rules.Rule{
		ID:      quickBlockID(target, now),
		Name:    "Quick block " + target,
		Enabled: &on,
		Mode:    rules.ModeEnforce,
		Action:  rules.ActionBlock,
		Match:   rules.Match{IPs: []string{target}},
		Expires: &expires,
		Note:    strings.TrimSpace(req.Note),
	}
	_, after, err := s.saveRules(r, m, append([]rules.Rule{rule}, existing...), configETag(current), "blocked "+target+" for "+req.Duration)
	if err != nil {
		writeRulesError(w, err)
		return
	}
	log.Printf("admin: quick block %s for %s", target, req.Duration)
	w.Header().Set("ETag", configETag(after))
	writeJSON(w, map[string]any{"id": rule.ID, "expires": expires})
}

// quickBlockID names a quick-block rule after its target and time, within
// the rule id alphabet: "block-203-0-113-7-kz3f1c".
func quickBlockID(target string, now time.Time) string {
	var b bytes.Buffer
	b.WriteString("block-")
	for _, c := range strings.ToLower(target) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		} else if b.Bytes()[b.Len()-1] != '-' {
			b.WriteByte('-')
		}
	}
	suffix := "-" + strconv.FormatInt(now.Unix(), 36)
	id := strings.TrimSuffix(b.String(), "-")
	if len(id)+len(suffix) > 64 {
		id = strings.TrimSuffix(id[:64-len(suffix)], "-")
	}
	return id + suffix
}
