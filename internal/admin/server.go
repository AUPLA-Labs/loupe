package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/apikeys"
	"github.com/AUPLA-Labs/loupe/internal/asn"
	"github.com/AUPLA-Labs/loupe/internal/aupldb"
	"github.com/AUPLA-Labs/loupe/internal/badip"
	"github.com/AUPLA-Labs/loupe/internal/bots"
	"github.com/AUPLA-Labs/loupe/internal/clientip"
	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
	"github.com/AUPLA-Labs/loupe/internal/rules"
	"github.com/AUPLA-Labs/loupe/internal/underattack"
	"github.com/AUPLA-Labs/loupe/internal/version"
)

//go:embed ui.html icons fonts
var uiFS embed.FS

// started is the process start time as the admin server sees it, for uptime.
var started = time.Now()

type Server struct {
	store       *Store
	reputation  *reputation.Store
	cfgPath     string
	auth        *auth
	listen      string
	allowed     atomic.Pointer[allowList]
	bots        atomic.Pointer[bots.Manager]
	robots      atomic.Pointer[RobotsPreviewFunc]
	badIPs      atomic.Pointer[badip.Feed]        // nil when bad_ips is disabled
	client      atomic.Pointer[clientip.Resolver] // nil: the socket address is the client
	asn         atomic.Pointer[ASNSource]
	audit       atomic.Pointer[Audit]          // nil is a no-op
	history     atomic.Pointer[config.History] // nil is a no-op
	rules       atomic.Pointer[rules.Manager]
	rulesTest   atomic.Pointer[RulesTestFunc]
	apiKeys     atomic.Pointer[apikeys.Store]
	underAttack atomic.Pointer[underattack.Switch]

	// cfgMu serialises writes of config.yaml with recording their version,
	// so the newest version is always the file's bytes.
	cfgMu sync.Mutex
}

// SetHistory connects the store of saved config.yaml and bots.yaml versions.
func (s *Server) SetHistory(h *config.History) { s.history.Store(h) }

// saveVersion stores data as the newest version of name and returns its id.
// Failing to record a version never fails the save that was already made: the
// error is logged and the id is "" unless the version was stored regardless
// (a prune failure after the write).
func (s *Server) saveVersion(name string, data []byte) string {
	id, err := s.history.Load().Save(name, data)
	if err != nil {
		log.Printf("admin: record %s version: %v", name, err)
	}
	return id
}

// diffDetail summarises the change from old to new for an audit entry.
func diffDetail(old, new []byte) string {
	added, removed := config.DiffStat(config.LineDiff(old, new))
	return fmt.Sprintf("+%d −%d lines", added, removed)
}

// SetBadIPs connects the external intel feed; nil means it's disabled.
func (s *Server) SetBadIPs(f *badip.Feed) { s.badIPs.Store(f) }

// RobotsPreviewFunc returns what /robots.txt on a host would serve now.
type RobotsPreviewFunc func(ctx context.Context, host string) (body, note string, err error)

// SetRobotsPreview connects the request handler's robots.txt preview.
func (s *Server) SetRobotsPreview(f RobotsPreviewFunc) { s.robots.Store(&f) }

// SetBots connects the bot policy manager, which the request handler owns
// and creates after the admin server is already listening.
func (s *Server) SetBots(m *bots.Manager) { s.bots.Store(m) }

// SetClientIP makes the console believe proxy.trusted proxies about who is
// signing in, for the sign-in throttle, sessions and the audit log.
func (s *Server) SetClientIP(rs *clientip.Resolver) { s.client.Store(rs) }

// NewServer builds the admin server. opts.Users may be empty to run without
// authentication — callers must only do that when the admin listener is
// bound to loopback only; config.Load enforces this. Login sessions persist
// in opts.SessionsPath, or only in memory when it is empty.
func NewServer(store *Store, reputationStore *reputation.Store, cfgPath string, opts AuthOptions) *Server {
	return &Server{store: store, reputation: reputationStore, cfgPath: cfgPath, auth: newAuth(opts)}
}

// route is one entry of the admin API. Every route that isn't a GET names the
// audit action it records, or "-" when it is deliberately left out. access
// says who may call it: "" lets a viewer GET and HEAD while every other
// method needs an admin, "self" lets any signed-in user, "admin" needs an
// admin even to read.
type route struct {
	pattern string
	h       http.HandlerFunc
	audit   string
	access  string
}

// allow wraps h with the route's access check. It runs before h, so a
// refused request has no effect and, wrapped around audited, leaves no
// audit entry. Any role other than admin is treated as read-only.
func (s *Server) allow(rt route, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := requestUser(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if s.auth != nil && s.auth.require2FA {
			// Read the secret from the store, so enrolling takes effect at
			// once. Until then the user may reach their own account routes
			// and the page that hosts the enrolment.
			cur, found := s.auth.users.get(u.Username)
			if !found {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if cur.TOTPSecret == "" && rt.access != "self" && rt.pattern != "GET /{$}" {
				http.Error(w, "two-factor enrolment required", http.StatusForbidden)
				return
			}
		}
		if u.Role != config.RoleAdmin {
			read := r.Method == http.MethodGet || r.Method == http.MethodHead
			if rt.access == "admin" || (rt.access == "" && !read) {
				http.Error(w, "read-only account", http.StatusForbidden)
				return
			}
		}
		h(w, r)
	}
}

func (s *Server) routes() []route {
	return []route{
		{"GET /{$}", s.handleUI, "", ""},
		{"POST /api/logout", s.auth.logout, "logout", "self"},
		{"GET /api/me", s.handleMe, "", "self"},
		{"POST /api/account/password", s.handleAccountPassword, "password_change", "self"},
		// Begin only holds a secret in memory until it is confirmed.
		{"POST /api/account/2fa/begin", s.handleEnrolBegin, "-", "self"},
		{"POST /api/account/2fa/confirm", s.handleEnrolConfirm, "2fa_enable", "self"},
		{"POST /api/account/2fa/disable", s.handleDisable2FA, "2fa_disable", "self"},
		{"POST /api/account/recovery", s.handleRecoveryRegenerate, "recovery_regenerate", "self"},
		{"GET /api/users", s.handleUsers, "", "admin"},
		{"POST /api/users", s.handleUserAdd, "user_add", "admin"},
		{"POST /api/users/role", s.handleUserRole, "user_role", "admin"},
		{"POST /api/users/password", s.handleUserPassword, "user_password", "admin"},
		{"POST /api/users/reset-2fa", s.handleUserReset2FA, "user_2fa_reset", "admin"},
		{"POST /api/users/remove", s.handleUserRemove, "user_remove", "admin"},
		{"GET /api/events", s.handleEvents, "", ""},
		{"GET /api/export", s.handleExport, "", ""},
		{"GET /api/stats", s.handleStats, "", ""},
		{"GET /api/pressure", s.handlePressure, "", ""},
		{"GET /api/ip", s.handleIP, "", ""},
		{"GET /api/asn", s.handleASN, "", ""},
		{"GET /api/health", s.handleHealth, "", ""},
		{"GET /api/stream", s.handleStream, "", ""},
		{"GET /api/audit", s.handleAudit, "", ""},
		{"GET /api/history", s.handleHistory, "", ""},
		{"GET /api/history/diff", s.handleHistoryDiff, "", ""},
		{"POST /api/history/restore", s.handleHistoryRestore, "history_restore", ""},
		{"GET /api/config", s.handleConfigGet, "", ""},
		{"POST /api/config", s.handleConfigSave, "config_save", ""},
		// Validate only parses the body and changes nothing, so it is not a
		// change to record.
		{"POST /api/config/validate", s.handleConfigValidate, "-", ""},
		{"GET /api/settings", s.handleSettingsGet, "", ""},
		{"POST /api/settings", s.handleSettingsSave, "settings_save", ""},
		{"POST /api/restart", s.handleRestart, "restart", ""},
		{"GET /api/bots", s.handleBots, "", ""},
		{"POST /api/bots/policy", s.handleBotsPolicy, "bots_policy", ""},
		{"POST /api/bots/refresh", s.handleBotsRefresh, "bots_refresh", ""},
		{"GET /api/bots/test", s.handleBotsTest, "", ""},
		{"GET /api/bots/robots", s.handleBotsRobots, "", ""},
		{"GET /api/rules", s.handleRulesGet, "", ""},
		{"POST /api/rules", s.handleRulesSave, "rules_save", ""},
		// The dry run answers and proxies nothing.
		{"POST /api/rules/test", s.handleRulesTest, "-", ""},
		{"POST /api/rules/quick-block", s.handleQuickBlock, "rules_quick_block", ""},
		{"GET /api/apikeys", s.handleAPIKeysGet, "", ""},
		{"POST /api/apikeys", s.handleAPIKeyCreate, "apikey_create", ""},
		{"POST /api/apikeys/revoke", s.handleAPIKeyRevoke, "apikey_revoke", ""},
		{"GET /api/under-attack", s.handleUnderAttackGet, "", ""},
		{"POST /api/under-attack", s.handleUnderAttackSet, "under_attack", ""},
		{"GET /api/badips", s.handleBadIPs, "", ""},
		{"POST /api/badips/refresh", s.handleBadIPsRefresh, "badips_refresh", ""},
		{"GET /api/network/terms", s.handleNetworkTerms, "", ""},
		{"POST /api/network/accept", s.handleNetworkAccept, "network_accept", ""},
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		h := rt.h
		if rt.audit != "" && rt.audit != "-" {
			h = s.audited(rt.audit, h)
		}
		mux.HandleFunc(rt.pattern, s.allow(rt, h))
	}

	// Everything the login page needs is reachable without a session.
	public := http.NewServeMux()
	public.Handle("GET /icons/", http.FileServerFS(uiFS))
	public.Handle("GET /fonts/", http.FileServerFS(uiFS))
	public.HandleFunc("GET /login", s.auth.loginPage)
	public.HandleFunc("POST /login", s.auth.login)
	public.HandleFunc("POST /login/2fa", s.auth.login2FA)
	public.HandleFunc("GET /setup/{token}", s.auth.setupPage)
	public.HandleFunc("POST /setup/{token}", s.auth.setup)
	public.Handle("/", s.auth.require(csrfGuard(mux)))
	return securityHeaders(s.withAllow(s.withClientIP(public)))
}

// headerTimeout bounds how long a client may take to send its request
// headers; a var so tests can shorten it.
var headerTimeout = 10 * time.Second

// HTTPServer builds the admin listener for addr. WriteTimeout stays 0
// because /api/stream is a long-lived SSE response that a write deadline would
// cut off; requests themselves are small, so reading one is bounded. Shutdown
// cancels the request contexts, so open streams end instead of holding it up.
func (s *Server) HTTPServer(addr string) *http.Server {
	s.listen = addr
	base, cancel := context.WithCancel(context.Background())
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		BaseContext:       func(net.Listener) context.Context { return base },
		ReadHeaderTimeout: headerTimeout,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	srv.RegisterOnShutdown(cancel)
	return srv
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	data, _ := uiFS.ReadFile("ui.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.Query(ParseQuery(r.URL.Query())))
}

// handleExport streams every matching event as CSV or JSON Lines for
// offline analysis. It honours the same filters as /api/events.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	q := ParseQuery(r.URL.Query())
	q.All = true
	events := s.store.Query(q).Events
	stamp := time.Now().Format("20060102-150405")

	switch r.URL.Query().Get("format") {
	case "json", "jsonl":
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="loupe-events-`+stamp+`.jsonl"`)
		enc := json.NewEncoder(w)
		for _, e := range events {
			enc.Encode(e)
		}
	default:
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="loupe-events-`+stamp+`.csv"`)
		cw := csv.NewWriter(w)
		cw.Write([]string{"time", "verdict_id", "action", "ip", "asn", "org", "method", "host", "path", "reason", "score", "signals", "pressure", "tier_floor", "tier", "external_sources", "user_agent"})
		for _, e := range events {
			asn := ""
			if e.ASN != 0 {
				asn = "AS" + strconv.FormatUint(uint64(e.ASN), 10)
			}
			cw.Write([]string{
				e.Time.Format(time.RFC3339), e.VID, e.Action, e.IP, asn, csvSafe(e.Org),
				e.Method, csvSafe(e.Host), csvSafe(e.Path), e.Reason, strconv.Itoa(e.Score),
				strings.Join(e.Reasons, " "), strconv.FormatFloat(e.Pressure, 'f', 2, 64),
				strconv.Itoa(e.TierFloor), strconv.Itoa(e.Tier), strconv.Itoa(e.BadIP), csvSafe(e.UA),
			})
		}
		cw.Flush()
	}
}

// csvSafe defuses spreadsheet formula injection: attacker-controlled fields
// (path, UA, host) starting with a formula trigger get a leading apostrophe.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.StatsFor(LookupWindow(r.URL.Query().Get("window")), time.Now()))
}

type pressureResponse struct {
	Entries       []pressureRow      `json:"entries"`
	Floors        map[string]float64 `json:"floors"`
	HalfLifeHours float64            `json:"half_life_hours"`
}

// pressureRow is a pressured key plus, for an IP, its external reputation:
// how many sources on the external intel feed report it and what that earns.
type pressureRow struct {
	reputation.PressureEntry
	External       int    `json:"external,omitempty"`
	ExternalAction string `json:"external_action,omitempty"`
	Name           string `json:"name,omitempty"` // AS name of an asn row, when known
}

// asnName returns asn's AS name from the event buffer (orgs) or the names
// already resolved, without looking up a network that was never named.
func (s *Server) asnName(asn uint, orgs map[uint]string) string {
	if n := orgs[asn]; n != "" {
		return n
	}
	if src := s.asnSource(); src != nil {
		return src.CachedName(asn)
	}
	return ""
}

func (s *Server) floors() map[string]float64 {
	f := s.reputation.Thresholds()
	return map[string]float64{"lumen_auto": f.Tier2, "singleclick": f.Tier3, "prism": f.Tier4}
}

func (s *Server) handlePressure(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 || n > 500 {
		n = 100
	}
	f := s.badIPs.Load()
	entries := []pressureRow{}
	var orgs map[uint]string
	for _, e := range s.reputation.TopPressured(n) {
		row := pressureRow{PressureEntry: e}
		if e.Kind == "asn" {
			if orgs == nil {
				orgs = s.store.OrgNames()
			}
			if a, err := strconv.ParseUint(strings.TrimPrefix(e.Key, "AS"), 10, 32); err == nil {
				row.Name = s.asnName(uint(a), orgs)
			}
		}
		if f != nil && e.Kind == "ip" {
			var act badip.Action
			if row.External, act = f.Check(net.ParseIP(e.Key)); row.External > 0 {
				row.ExternalAction = act.String()
			}
		}
		entries = append(entries, row)
	}
	writeJSON(w, pressureResponse{
		Entries:       entries,
		Floors:        s.floors(),
		HalfLifeHours: s.reputation.HalfLife().Hours(),
	})
}

func (s *Server) handleIP(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "missing ip", http.StatusBadRequest)
		return
	}
	p := s.store.Profile(ip)
	if src := s.asnSource(); src != nil {
		// A client key can be an IPv6 /64; its first address stands for it.
		addr := net.ParseIP(ip)
		if pfx, err := netip.ParsePrefix(ip); err == nil {
			addr = net.IP(pfx.Addr().AsSlice())
		}
		if addr != nil {
			if rec, err := src.Lookup(addr); err == nil {
				p.Network = &rec
				if p.ASN == 0 {
					p.ASN, p.Org = rec.ASN, rec.Org
				}
			}
		}
	}
	p.Pressure = s.reputation.IPPressure(ip)
	p.TierFloor = s.reputation.FloorName(p.Pressure)
	if p.ASN != 0 {
		p.ASNPressure = s.reputation.ASNPressure(p.ASN)
		p.ASNTierFloor = s.reputation.FloorName(p.ASNPressure)
	}
	if f := s.badIPs.Load(); f != nil {
		p.BadIP, p.BadIPAction = f.Check(net.ParseIP(ip))
		p.BadIPActionName = p.BadIPAction.String()
	}
	writeJSON(w, struct {
		IPProfile
		Floors map[string]float64 `json:"floors"`
	}{p, s.floors()})
}

// handleASN profiles one network: its traffic in the buffer, the addresses
// seen from it with their own pressure and external rating, and the
// network's pressure against the floors that apply to it.
func (s *Server) handleASN(w http.ResponseWriter, r *http.Request) {
	a, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("asn"))), "AS"), 10, 32)
	if err != nil || a == 0 {
		http.Error(w, "asn must be a number like 15169 or AS15169", http.StatusBadRequest)
		return
	}
	n := uint(a)
	p := s.store.ASNProfile(n)
	if p.Org == "" {
		p.Org = s.asnName(n, nil)
	}
	if src := s.asnSource(); src != nil {
		if info := src.Info(n); info != (asn.ASNInfo{}) {
			p.Info = &info
			if p.Org == "" {
				p.Org = info.Name
			}
		}
		p.Datacenter = src.IsDatacenter(n)
		switch {
		case src.IsBlocked(n):
			p.Listed = "blocked"
		case src.IsAllowed(n):
			p.Listed = "allowed"
		}
	}
	p.Pressure = s.reputation.ASNPressure(n)
	p.TierFloor = s.reputation.ASNFloorName(p.Pressure, p.Datacenter)
	t := s.reputation.ASNThresholds(p.Datacenter)
	p.Floors = map[string]float64{"lumen_auto": t.Tier2, "singleclick": t.Tier3, "prism": t.Tier4}
	f := s.badIPs.Load()
	for i := range p.IPs {
		c := &p.IPs[i]
		c.Pressure = s.reputation.IPPressure(c.IP)
		if c.Pressure > 0 {
			c.TierFloor = s.reputation.FloorName(c.Pressure)
		}
		if f != nil {
			var act badip.Action
			if c.BadIP, act = f.Check(net.ParseIP(c.IP)); c.BadIP > 0 {
				c.BadIPAct = act.String()
				p.BadIPs++
			}
		}
	}
	writeJSON(w, struct {
		ASNProfile
		IPFloors map[string]float64 `json:"ip_floors"`
	}{p, s.floors()})
}

type health struct {
	Status        string         `json:"status"`
	Version       string         `json:"version"`
	Revision      string         `json:"revision,omitempty"`
	RevisionTime  string         `json:"revision_time,omitempty"`
	Modified      bool           `json:"modified"`
	GoVersion     string         `json:"go_version"`
	Hostname      string         `json:"hostname"`
	PID           int            `json:"pid"`
	Started       time.Time      `json:"started"`
	UptimeSeconds int64          `json:"uptime_seconds"`
	Goroutines    int            `json:"goroutines"`
	HeapBytes     uint64         `json:"heap_bytes"`
	SysBytes      uint64         `json:"sys_bytes"`
	NumGC         uint32         `json:"num_gc"`
	Buffer        BufferInfo     `json:"buffer"`
	Subscribers   int            `json:"subscribers"`
	ConfigPath    string         `json:"config_path"`
	ConfigMtime   time.Time      `json:"config_mtime,omitempty"`
	Listen        string         `json:"listen,omitempty"`
	AuthEnabled   bool           `json:"auth_enabled"`
	PressureKeys  int            `json:"pressure_keys"`
	ASN           *aupldb.Status `json:"asn,omitempty"`
	// Overlay is the state of every published list Loupe fetches (Tor
	// exits, VPN servers, cloud ranges, verified crawlers).
	Overlay []aupldb.ListStatus `json:"overlay,omitempty"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	h := health{
		Status:        "ok",
		Version:       "dev",
		GoVersion:     runtime.Version(),
		PID:           os.Getpid(),
		Started:       started,
		UptimeSeconds: int64(time.Since(started).Seconds()),
		Goroutines:    runtime.NumGoroutine(),
		HeapBytes:     ms.HeapAlloc,
		SysBytes:      ms.Sys,
		NumGC:         ms.NumGC,
		Buffer:        s.store.Buffer(),
		Subscribers:   s.store.Subscribers(),
		ConfigPath:    s.cfgPath,
		Listen:        s.listen,
		AuthEnabled:   s.auth != nil,
		PressureKeys:  len(s.reputation.TopPressured(1 << 30)),
	}
	if src := s.asnSource(); src != nil {
		st := src.Status()
		h.ASN = &st
		h.Overlay = src.OverlayStatus()
	}
	h.Hostname, _ = os.Hostname()
	if fi, err := os.Stat(s.cfgPath); err == nil {
		h.ConfigMtime = fi.ModTime()
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			h.Version = bi.Main.Version
		}
		if version.Version != "" {
			h.Version = version.Version
		}
		for _, st := range bi.Settings {
			switch st.Key {
			case "vcs.revision":
				h.Revision = st.Value
			case "vcs.time":
				h.RevisionTime = st.Value
			case "vcs.modified":
				h.Modified = st.Value == "true"
			}
		}
	}
	writeJSON(w, h)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := s.store.Subscribe()
	defer s.store.Unsubscribe(ch)

	fmt.Fprintf(w, "retry: 3000\n: connected\n\n")
	flusher.Flush()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case e, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

// configETag fingerprints config contents so a save can detect that the file
// changed on disk since the editor loaded it.
func configETag(b []byte) string {
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:12]) + `"`
}

func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.cfgPath)
	if err != nil {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("ETag", configETag(data))
	w.Write(data)
}

func (s *Server) readConfigBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 256*1024))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return nil, false
	}
	if _, err := s.validateCandidate(body); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return nil, false
	}
	return body, true
}

// validateCandidate loads a config the dashboard is about to write. Unlike
// startup, which tolerates an admin.auth_file that can't be loaded so the
// proxy keeps serving, a write must refuse it: saving it would lock every
// admin out at the next restart.
func (s *Server) validateCandidate(data []byte) (*config.Config, error) {
	cfg, err := config.LoadBytes(data)
	if err != nil {
		return nil, err
	}
	if cfg.Admin.AuthError != "" {
		return nil, errors.New(cfg.Admin.AuthError)
	}
	if cfg.Admin.NeedsSetup && s.auth != nil && s.auth.users.path != "" {
		// Startup would offer a setup link; from a console whose admins
		// come from a users file, one that isn't there is a mistake.
		if n, _ := s.auth.users.state(); n > 0 {
			return nil, fmt.Errorf("admin.auth_file: %s does not exist", cfg.Admin.AuthFile)
		}
	}
	return cfg, nil
}

func (s *Server) handleConfigValidate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.readConfigBody(w, r); ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleConfigSave(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readConfigBody(w, r)
	if !ok {
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	current, err := os.ReadFile(s.cfgPath)
	if err != nil && !os.IsNotExist(err) {
		http.Error(w, "read config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if m := r.Header.Get("If-Match"); m != "" && m != configETag(current) {
		http.Error(w, "config.yaml changed on disk since it was loaded — reload and reapply your edits", http.StatusPreconditionFailed)
		return
	}
	if err := writeFileAtomic(s.cfgPath, body, 0600); err != nil {
		http.Error(w, "write config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	version := s.saveVersion("config", body)
	noteAudit(r, "config.yaml", diffDetail(current, body), version)
	log.Printf("admin: config saved (%d bytes)", len(body))
	w.Header().Set("ETag", configETag(body))
	w.WriteHeader(http.StatusNoContent)
}

// writeFileAtomic writes data to a temp file in path's directory and renames
// it over path, so a crash mid-write never leaves a truncated config. The
// mode is forced since this file may hold a legacy inline hmac_secret (normally
// it lives in hmac_secret_file) and admin.auth_file's path.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
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

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusAccepted)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	log.Println("admin: restart requested")
	go func() {
		time.Sleep(100 * time.Millisecond)
		syscall.Kill(os.Getpid(), syscall.SIGTERM)
	}()
}

func (s *Server) botsOr503(w http.ResponseWriter) *bots.Manager {
	m := s.bots.Load()
	if m == nil {
		http.Error(w, "bot policy is still starting up", http.StatusServiceUnavailable)
	}
	return m
}

func (s *Server) handleBots(w http.ResponseWriter, r *http.Request) {
	m := s.botsOr503(w)
	if m == nil {
		return
	}
	writeJSON(w, struct {
		bots.Directory
		Stats map[string]*BotStat `json:"stats"`
	}{m.Directory(), s.store.BotStats(time.Now().Add(-24 * time.Hour))})
}

func (s *Server) handleBotsPolicy(w http.ResponseWriter, r *http.Request) {
	m := s.botsOr503(w)
	if m == nil {
		return
	}
	var p bots.Policy
	dec := json.NewDecoder(io.LimitReader(r.Body, 256*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		http.Error(w, "bad policy: "+err.Error(), http.StatusBadRequest)
		return
	}
	before, _ := os.ReadFile(m.PolicyFile())
	saved, err := m.Save(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	after, _ := os.ReadFile(m.PolicyFile())
	noteAudit(r, "bots.yaml", diffDetail(before, after), s.botsVersion(after))
	log.Printf("admin: bot policy saved")
	writeJSON(w, saved)
}

// botsVersion returns the id of the newest bots version if it holds exactly
// the policy file's current bytes, else "". The manager's hook records the
// version, so when that failed (or no hook is wired, or the policy is
// memory-only) the newest version is an older save and must not be linked.
func (s *Server) botsVersion(current []byte) string {
	h := s.history.Load()
	vs, err := h.List("bots")
	if err != nil {
		log.Printf("admin: list bots versions: %v", err)
		return ""
	}
	if len(vs) == 0 || len(current) == 0 {
		return ""
	}
	if got, err := h.Get("bots", vs[0].ID); err != nil || !bytes.Equal(got, current) {
		return ""
	}
	return vs[0].ID
}

func (s *Server) handleBotsRefresh(w http.ResponseWriter, r *http.Request) {
	m := s.botsOr503(w)
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	m.RefreshAll(ctx)
	writeJSON(w, m.Directory().Sources)
}

func (s *Server) handleBotsTest(w http.ResponseWriter, r *http.Request) {
	m := s.botsOr503(w)
	if m == nil {
		return
	}
	q := r.URL.Query()
	ip := net.ParseIP(strings.TrimSpace(q.Get("ip")))
	if ip == nil && strings.TrimSpace(q.Get("ip")) != "" {
		http.Error(w, "not an IP address", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	writeJSON(w, m.Explain(ctx, ip, q.Get("ua")))
}

func (s *Server) handleBotsRobots(w http.ResponseWriter, r *http.Request) {
	m := s.botsOr503(w)
	f := s.robots.Load()
	if m == nil {
		return
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	resp := struct {
		Mode    bots.RobotsMode `json:"mode"`
		Section string          `json:"section"`
		Signals map[string]bool `json:"signals"`
		Host    string          `json:"host,omitempty"`
		Body    string          `json:"body"`
		Note    string          `json:"note,omitempty"`
		Error   string          `json:"error,omitempty"`
	}{Mode: m.RobotsMode(), Section: m.RobotsSection(), Signals: m.ContentSignals(), Host: host}
	if host != "" && f != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		var err error
		if resp.Body, resp.Note, err = (*f)(ctx, host); err != nil {
			resp.Error = err.Error()
		}
	}
	writeJSON(w, resp)
}

func (s *Server) handleBadIPs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.badIPs.Load().Status())
}

func (s *Server) handleBadIPsRefresh(w http.ResponseWriter, r *http.Request) {
	f := s.badIPs.Load()
	if f == nil {
		http.Error(w, "the external intel feed is turned off — enable it under Settings, then restart", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := f.Refresh(ctx); err != nil {
		http.Error(w, "refresh failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	log.Printf("admin: external intel feed refreshed")
	writeJSON(w, f.Status())
}
