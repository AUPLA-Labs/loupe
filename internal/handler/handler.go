package handler

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/admin"
	"github.com/AUPLA-Labs/loupe/internal/apikeys"
	"github.com/AUPLA-Labs/loupe/internal/asn"
	"github.com/AUPLA-Labs/loupe/internal/badip"
	"github.com/AUPLA-Labs/loupe/internal/bots"
	"github.com/AUPLA-Labs/loupe/internal/clientip"
	"github.com/AUPLA-Labs/loupe/internal/config"
	"github.com/AUPLA-Labs/loupe/internal/cookie"
	"github.com/AUPLA-Labs/loupe/internal/lumen"
	"github.com/AUPLA-Labs/loupe/internal/offender"
	"github.com/AUPLA-Labs/loupe/internal/proof"
	"github.com/AUPLA-Labs/loupe/internal/ratelimit"
	"github.com/AUPLA-Labs/loupe/internal/reputation"
	"github.com/AUPLA-Labs/loupe/internal/rules"
	"github.com/AUPLA-Labs/loupe/internal/tier"
	"github.com/AUPLA-Labs/loupe/internal/underattack"
)

//go:embed challenge.html blocked.html ratelimited.html prism.html pulse.html unverified.html footer.html wordmark.html proof.js fingerprint.js fonts
var staticFiles embed.FS

type Handler struct {
	cfg                   *config.Config
	asnDB                 *asn.DB
	lumenCheck            *lumen.Verifier
	cookies               *cookie.Manager
	proxy                 *httputil.ReverseProxy
	client                *clientip.Resolver
	proxyWarn             sync.Once // the proxy.client_ip_header warning
	tmpl                  *template.Template
	blockedTpl            *template.Template
	rateLimitedTpl        *template.Template
	prismTmpl             *template.Template
	pulseTmpl             *template.Template
	unverifiedTpl         *template.Template
	fontsPath             string
	lumenPath             string
	prismPath             string
	pulsePath             string
	pulseResultPath       string
	noJSPath              string
	noCookiesPath         string
	unverifiedPath        string
	challengeRL           *ratelimit.Limiter // rate limit on /loupe/lumen
	verifyRL              *ratelimit.Limiter // rate limit on /loupe/verify
	prismRL               *ratelimit.Limiter // rate limit on /loupe/prism and /loupe/prism/verify
	pulseRL               *ratelimit.Limiter // rate limit on /loupe/pulse/verify
	pulsePageRL           *ratelimit.Limiter // rate limit on /loupe/pulse (each hit issues a proof challenge)
	unclearedRL           *ratelimit.Limiter // rate limit on proxied requests without clearance
	clearanceDocRL        *ratelimit.Limiter // per-cookie document budget
	clearanceAllRL        *ratelimit.Limiter // per-cookie budget for all requests
	clearance             *clearanceState
	bots                  *bots.Manager
	robots                *robotsCache
	offenders             *offender.Tracker
	escalations           *offender.Escalations
	reputation            *reputation.Store
	badIPs                *badip.Feed // nil when bad_ips is disabled
	rules                 *rules.Manager
	apiKeys               *apikeys.Store // keys for api rules with auth: loupe_keys
	underAttack           *underattack.Switch
	behaviour             *behaviour
	limits                *requestLimits
	badBotUAs             []string // extra patterns merged with defaultBotUAPatterns
	store                 *admin.Store
	rollups               *rollups // nil: every event is logged individually
	stopRollups           chan struct{}
	automationArtifactsJS template.JS
	nativeFnNamesJS       template.JS
	proofs                *proof.Store
	clusters              *clusterTracker
	proofJS               template.JS
	fingerprintJS         template.JS
}

func New(cfg *config.Config, store *admin.Store, repStore *reputation.Store) (*Handler, error) {
	asnDB, err := asn.New(asn.Options{
		Path:       cfg.ASN.DBPath,
		API:        cfg.ASN.APIURL,
		TokenFile:  cfg.ASN.TokenFile,
		PublicKeys: cfg.ASN.PublicKeys,
		Interval:   time.Duration(cfg.ASN.RefreshMinutes) * time.Minute,
		// Unset means [hosting] (config defaults); an explicit [] means none.
		DatacenterCategories:  cfg.ASN.DatacenterCategories,
		OverlayDir:            overlayDir(cfg.ASN.OverlayDir),
		UserAgent:             "Loupe (+https://auplalabs.com/loupe)",
		DatacenterListURL:     datacenterListURL(cfg.ASN.DatacenterASNsURL),
		DatacenterListRefresh: time.Duration(cfg.ASN.DatacenterASNsRefreshHours) * time.Hour,
		OnName: func(n uint, name string) {
			if store != nil {
				store.FillOrg(n, name)
			}
		},
	}, cfg.ASN.BlockedASNs, cfg.ASN.AllowedASNs, cfg.ASN.DatacenterASNs, cfg.ASN.DatacenterASNsFile)
	if err != nil {
		return nil, fmt.Errorf("asn db: %w", err)
	}

	if store != nil {
		store.SetOrgLookup(asnDB.NameOf)
		asnDB.QueueNames(store.ASNsWithoutOrg()) // events from before a restart
	}

	botMgr, err := bots.New(bots.Options{
		PolicyFile: cfg.Bots.PolicyFile,
		RangesDir:  cfg.Bots.RangesDir,
		Refresh:    time.Duration(cfg.Bots.RefreshHours) * time.Hour,
		VerifyTTL:  time.Duration(cfg.GoodBots.TTL) * time.Second,
		ASN: func(ip net.IP) uint {
			rec, err := asnDB.Lookup(ip)
			if err != nil {
				return 0
			}
			return rec.ASN
		},
		Legacy: legacyBots(cfg),
	})
	if err != nil {
		return nil, err
	}

	backendURL, err := url.Parse(cfg.Backend)
	if err != nil {
		return nil, fmt.Errorf("backend url: %w", err)
	}

	tmpl, err := parsePage("challenge", "challenge.html")
	if err != nil {
		return nil, err
	}

	blockedTpl, err := parsePage("blocked", "blocked.html")
	if err != nil {
		return nil, err
	}
	rateLimitedTpl, err := parsePage("ratelimited", "ratelimited.html")
	if err != nil {
		return nil, err
	}

	prismTmpl, err := parsePage("prism", "prism.html")
	if err != nil {
		return nil, err
	}

	pulseTmpl, err := parsePage("pulse", "pulse.html")
	if err != nil {
		return nil, err
	}

	unverifiedTpl, err := parsePage("unverified", "unverified.html")
	if err != nil {
		return nil, err
	}

	proofJS, err := staticFiles.ReadFile("proof.js")
	if err != nil {
		return nil, fmt.Errorf("read proof.js: %w", err)
	}
	fpJS, err := staticFiles.ReadFile("fingerprint.js")
	if err != nil {
		return nil, fmt.Errorf("read fingerprint.js: %w", err)
	}

	prefix := path.Dir(cfg.ChallengePath)

	badBotUAs := make([]string, 0, len(cfg.BadBotUAs.Patterns))
	for _, p := range cfg.BadBotUAs.Patterns {
		badBotUAs = append(badBotUAs, strings.ToLower(p))
	}
	if cfg.BadBotUAs.PatternsFile != "" {
		filePatterns, err := loadUAPatternsFile(cfg.BadBotUAs.PatternsFile)
		if err != nil {
			return nil, fmt.Errorf("bad_bot_uas.patterns_file: %w", err)
		}
		badBotUAs = append(badBotUAs, filePatterns...)
	}

	automationArtifactsJS, err := jsStringArray(cfg.Hardening.AutomationArtifacts)
	if err != nil {
		return nil, fmt.Errorf("hardening.automation_artifacts: %w", err)
	}

	nativeFnNamesJS, err := jsStringArray(cfg.Hardening.NativeFnNames)
	if err != nil {
		return nil, fmt.Errorf("hardening.native_fn_names: %w", err)
	}

	h := &Handler{
		cfg:                   cfg,
		asnDB:                 asnDB,
		lumenCheck:            lumen.NewVerifier(cfg.Lumen.MaxConcurrentChecks),
		cookies:               cookie.New(cfg.HMACSecret, cfg.CookieName, cfg.CookieTTL),
		tmpl:                  tmpl,
		blockedTpl:            blockedTpl,
		rateLimitedTpl:        rateLimitedTpl,
		prismTmpl:             prismTmpl,
		pulseTmpl:             pulseTmpl,
		unverifiedTpl:         unverifiedTpl,
		fontsPath:             prefix + "/fonts/",
		lumenPath:             prefix + "/lumen",
		prismPath:             prefix + "/prism",
		pulsePath:             prefix + "/pulse",
		pulseResultPath:       prefix + "/pulse/verify",
		noJSPath:              prefix + "/no-js",
		noCookiesPath:         prefix + "/no-cookies",
		unverifiedPath:        prefix + "/unverified",
		challengeRL:           ratelimit.New(1, 6),
		verifyRL:              ratelimit.New(0.5, 4),
		prismRL:               ratelimit.New(0.5, 4),
		pulseRL:               ratelimit.New(1, 10),
		pulsePageRL:           ratelimit.New(1, 10),
		unclearedRL:           ratelimit.New(cfg.Abuse.RateLimit.Rate, cfg.Abuse.RateLimit.Burst),
		clearanceDocRL:        ratelimit.New(cfg.Abuse.ClearanceBudget.DocRate, cfg.Abuse.ClearanceBudget.DocBurst),
		clearanceAllRL:        ratelimit.New(cfg.Abuse.ClearanceBudget.AllRate, cfg.Abuse.ClearanceBudget.AllBurst),
		clearance:             newClearanceState(),
		bots:                  botMgr,
		offenders:             offender.New(cfg.Abuse.FailThreshold, time.Duration(cfg.Abuse.CooldownSeconds)*time.Second),
		escalations:           offender.NewEscalations(),
		reputation:            repStore,
		rules:                 rules.NewManager(cfg.Rules.File),
		apiKeys:               apikeys.New(filepath.Join(filepath.Dir(cfg.Rules.File), "api_keys.yaml")),
		behaviour:             newBehaviour(),
		underAttack:           underattack.New(filepath.Join(filepath.Dir(cfg.Rules.File), "under_attack.json")),
		limits:                newRequestLimits(cfg.Limits),
		badBotUAs:             badBotUAs,
		store:                 store,
		automationArtifactsJS: automationArtifactsJS,
		nativeFnNamesJS:       nativeFnNamesJS,
		proofs:                proof.NewStore(proofStoreMax),
		clusters:              newClusterTracker(),
		proofJS:               template.JS(proofJS),
		fingerprintJS:         template.JS(fpJS),
	}
	if cfg.BadIPs.Enabled {
		h.badIPs = badip.New(badip.Options{
			URL:         cfg.BadIPs.URL,
			CacheFile:   cfg.BadIPs.CacheFile,
			Refresh:     time.Duration(cfg.BadIPs.RefreshHours) * time.Hour,
			ChallengeAt: cfg.BadIPs.ChallengeAt,
			BlockAt:     cfg.BadIPs.BlockAt,
		})
	}
	if e := h.rules.LoadErr(); e != "" {
		log.Printf("rules: %s; running with no rules", e)
	} else {
		log.Printf("rules: %d loaded from %s", h.rules.Set().Len(), h.rules.Path())
	}
	if h.client, err = clientip.New(cfg.Proxy.Trusted, cfg.Proxy.ClientIPHeader); err != nil {
		return nil, err
	}
	h.proxy = h.buildProxy(backendURL)
	h.robots = newRobotsCache(backendURL)
	h.rollups, h.stopRollups = newRollups(h.emit), make(chan struct{})
	go h.rollups.run(h.stopRollups)
	return h, nil
}

// Close logs the event summaries still accumulating, so a restart doesn't
// lose their counts. Call it before closing the event store.
func (h *Handler) Close() {
	if h.apiKeys != nil {
		h.apiKeys.Close()
	}
	if h.rollups == nil {
		return
	}
	close(h.stopRollups)
	h.rollups.flush(true)
}

// buildProxy creates a reverse proxy that preserves the Host header so the
// backend can do name-based virtual hosting correctly.
func (h *Handler) buildProxy(target *url.URL) *httputil.ReverseProxy {
	// The default transport has no dial or response-header timeout, so a hung
	// backend would pin a goroutine and connection per request indefinitely.
	// The body is not bounded, so slow or streamed responses still work.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	tr.ResponseHeaderTimeout = 60 * time.Second
	tr.MaxIdleConnsPerHost = 64
	return &httputil.ReverseProxy{
		Transport: tr,
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			if req.Header.Get("X-Forwarded-Proto") == "" {
				req.Header.Set("X-Forwarded-Proto", requestScheme(req))
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				// The body ran past limits.max_body_bytes while being sent on.
				http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
				return
			}
			log.Printf("proxy error: %v", err)
			http.Error(w, "Bad gateway", http.StatusBadGateway)
		},
		ModifyResponse: func(resp *http.Response) error {
			// HTML responses are gated by the Clearance cookie, so the browser
			// must not serve a cached copy when the cookie is absent or
			// different (changed IP, expiry). Vary: Cookie causes a cache
			// miss whenever the cookie value changes; Cache-Control: private
			// stops CDNs (Cloudflare) from caching authenticated pages.
			if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
				cc := resp.Header.Get("Cache-Control")
				if !strings.Contains(cc, "private") && !strings.Contains(cc, "no-store") {
					if cc == "" {
						resp.Header.Set("Cache-Control", "private")
					} else {
						resp.Header.Set("Cache-Control", cc+", private")
					}
				}
				vary := resp.Header.Get("Vary")
				if vary == "" {
					resp.Header.Set("Vary", "Cookie")
				} else if !strings.Contains(strings.ToLower(vary), "cookie") {
					resp.Header.Set("Vary", vary+", Cookie")
				}
			}
			return nil
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = withNewVerdict(w, h.normalise(r))

	// Oversized and malformed requests are refused before anything else.
	ip := h.realIP(r)
	if h.enforceLimits(w, r, ip) {
		return
	}

	// Internal Loupe endpoints — served before any other logic.
	switch r.URL.Path {
	case h.cfg.ChallengePath:
		h.serveChallengePage(w, r)
		return
	case h.cfg.VerifyPath:
		if !h.verifyRL.Allow(h.ipKey(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h.serveVerify(w, r)
		return
	case h.lumenPath:
		if !h.challengeRL.Allow(h.ipKey(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h.serveLumenChallenge(w, r)
		return
	case h.prismPath:
		if !h.prismRL.Allow(h.ipKey(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h.servePrism(w, r)
		return
	case h.prismPath + "/verify":
		if !h.prismRL.Allow(h.ipKey(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h.servePrismVerify(w, r)
		return
	case h.pulsePath:
		if !h.pulsePageRL.Allow(h.ipKey(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h.servePulse(w, r)
		return
	case h.pulseResultPath:
		if !h.pulseRL.Allow(h.ipKey(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h.servePulseResult(w, r)
		return
	case h.noJSPath:
		if !h.pulseRL.Allow(h.ipKey(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h.serveNoJS(w, r)
		return
	case h.noCookiesPath:
		if !h.pulseRL.Allow(h.ipKey(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h.serveNoCookies(w, r, safeReturnURL(r.URL.Query().Get("return")))
		return
	case h.unverifiedPath:
		if !h.pulseRL.Allow(h.ipKey(r)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		h.serveUnverifiable(w, r, "", safeReturnURL(r.URL.Query().Get("return")))
		return
	}

	// The operator's rules (rules.yaml) run before everything else, so an
	// allow rule skips every check and a block rule also covers public paths
	// and clients holding a clearance cookie. Private addresses never reach
	// them. A challenge rule only raises the tier at dispatch, below.
	var done bool
	if r, done = h.runRules(w, r, ip); done {
		return
	}
	// An api rule (rules.yaml) serves the route to non-browser clients:
	// they skip the browser-only steps below, and serveAPI replaces the
	// challenge. Blocks still apply.
	api := apiPolicyOf(r)

	// Public assets and crawler-facing files (favicons, robots.txt, .well-known/)
	// are proxied directly without any Loupe checks.
	if isPublicPath(r.URL.Path) {
		h.emitLoggedAllow(r, "public_path")
		if r.URL.Path == "/robots.txt" && h.serveRobots(w, r) {
			return
		}
		h.proxyThrough(w, r)
		return
	}

	// Embedded font files.
	if strings.HasPrefix(r.URL.Path, h.fontsPath) {
		h.emitLoggedAllow(r, "font")
		name := strings.TrimPrefix(r.URL.Path, h.fontsPath)
		sub, err := fs.Sub(staticFiles, "fonts")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		http.ServeFileFS(w, r, sub, name)
		return
	}

	// Valid pass cookie → straight through, provided this request is
	// consistent with the client the cookie was issued to and within the
	// cookie's budget (checkClearance). Also proof this client's cookies
	// work at all, so any answered-without-clearance streak it was building
	// no longer indicates a loop in progress.
	//
	// An address the bad-IP feed says to block skips this: a clearance
	// earned before the list named it doesn't outlive the listing.
	if c, valid := h.cookies.Check(r, h.ipKey(r)); valid && !h.badIPBlocked(r) && (api == nil || api.CookieAllowed()) {
		reasons, hostile := h.checkClearance(r, c)
		// Post-clearance behaviour (behaviour.go): recorded on the event,
		// and with behaviour.enforce a high score drops the clearance.
		var bScore int
		var bReasons []string
		if len(reasons) == 0 && isDocumentNavigation(r) && !isPrivateIP(ip) {
			bScore, bReasons = h.behaviour.Observe(c.ID, r, time.Now())
			if h.cfg.Behaviour.Enforce && bScore >= behaviourThreshold {
				h.clearance.revoke(c.ID, c.Expiry)
				asnNum, _, _ := h.clientASN(r)
				h.reputation.Record(h.ipKey(r), asnNum, reputation.BehaviourAnomaly)
				reasons = append([]string{"clearance_behaviour"}, bReasons...)
			}
		}
		if len(reasons) == 0 {
			h.offenders.ClearAnsweredNoClearance(h.ipKey(r))
			// Logged per run, not per request: a web app's assets and API
			// calls would bury every other event. Page navigations stay
			// visible on their own.
			ev := h.newEvent(r, h.ipKey(r), 0, "", "ALLOW", "clearance", bScore)
			ev.Reasons = bReasons
			h.emitRolled(rollupKey{"ALLOW", "clearance", h.ipKey(r), r.Host, r.UserAgent(), loggedRules(r)},
				ev, isDocumentNavigation(r))
			h.proxyThrough(w, r)
			return
		}
		// The request continues as an uncleared one: a navigation gets a
		// fresh interstitial, anything else a 403.
		h.dropClearance(w, r, c, reasons, hostile)
	}

	// Private/loopback IPs (health checks, local tooling) pass without challenge.
	if isPrivateIP(ip) {
		h.proxyThrough(w, r)
		return
	}

	// Backstop: a client that keeps answering challenges but never retains
	// the resulting clearance cookie is stuck in an infinite redirect loop.
	// Checked early, before repeat-offender and bot classification, because
	// this is a real-browser failure mode to explain, not abuse to block.
	//
	// The explanation is served once per streak, then the streak resets:
	// nothing on this path can earn a clearance, so a sticky backstop would
	// lock the whole address out until the counter expired, even after the
	// browser was fixed (seen live after a UA switcher was turned off). A
	// browser that really drops cookies just loops back here after another
	// noCookiesThreshold answers.
	if api == nil && h.shouldServeNoCookies(h.ipKey(r)) {
		h.serveNoCookies(w, r, safeReturnURL(r.URL.RequestURI()))
		h.offenders.ClearAnsweredNoClearance(h.ipKey(r))
		return
	}

	// Repeat offenders: too many consecutive challenge/verification failures
	// gets a hard block for a cooldown instead of an endless stream of fresh,
	// equally-easy challenges. Checked early so it short-circuits everything else.
	if h.offenders.Blocked(h.ipKey(r)) {
		log.Printf("BLOCK repeat_offender ip=%s ua=%q path=%s", ip, r.UserAgent(), r.URL.Path)
		h.emit(h.newEvent(r, h.ipKey(r), 0, "", "BLOCK", "repeat_offender", 0))
		h.serveBlocked(w, r)
		return
	}

	// Known bots (search engines, AI crawlers, link previews, monitors…):
	// the site's bot policy decides. Allow only ever applies to a request
	// whose IP the operator vouches for (published list, own network or
	// reverse DNS) — the User-Agent alone never skips protection. Standard
	// falls through to the normal pipeline below, tagged with the claim so
	// its events show which bot it pretended or turned out to be.
	if d := h.classifyBot(ip, r.UserAgent()); d.Bot != nil {
		r = r.WithContext(context.WithValue(r.Context(), botClaimKey{}, d))
		switch d.Action {
		case bots.Allow:
			log.Printf("ALLOW verified_bot=%s via=%q ip=%s ua=%q", d.Bot.ID, d.Method, ip, r.UserAgent())
			h.emit(h.newEvent(r, h.ipKey(r), 0, "", "ALLOW", "verified_bot", 0))
			h.proxyThrough(w, r)
			return
		case bots.Block:
			reason := "bot_blocked"
			switch {
			case d.Spoofed:
				reason = "spoofed_bot"
			case d.Unverifiable:
				reason = "unverifiable_bot"
			}
			log.Printf("BLOCK %s=%s ip=%s ua=%q", reason, d.Bot.ID, ip, r.UserAgent())
			h.emit(h.newEvent(r, h.ipKey(r), 0, "", "BLOCK", reason, 0))
			h.serveBlocked(w, r)
			return
		}
	}

	// Block known automation tools and scanners by User-Agent. An api
	// route expects HTTP client libraries and refuses only scanners.
	if api == nil && isKnownBotUA(r.UserAgent(), h.badBotUAs) || api != nil && isScannerUA(r.UserAgent(), h.badBotUAs) {
		log.Printf("BLOCK bot_ua ip=%s ua=%q path=%s", ip, r.UserAgent(), r.URL.Path)
		h.emit(h.newEvent(r, h.ipKey(r), 0, "", "BLOCK", "bot_ua", 0))
		h.serveBlocked(w, r)
		return
	}

	// Everything above this point has either passed the request through
	// (clearance, private IP, verified bot, allowed crawler) or blocked it
	// outright. What remains is traffic that is about to be challenged, and a
	// real visitor produces only one or two such requests — so a low limit here
	// caps a flood without touching ordinary browsing.
	if api == nil && !h.unclearedRL.Allow(h.ipKey(r)) {
		h.emitRolled(rollupKey{"LIMIT", "rate_limited", h.ipKey(r), r.Host, "", loggedRules(r)},
			h.newEvent(r, h.ipKey(r), 0, "", "LIMIT", "rate_limited", 0), false)
		h.serveRateLimited(w, r, time.Minute)
		return
	}

	rec, err := h.asnDB.Lookup(ip)
	if err != nil && api == nil {
		log.Printf("ASN lookup error ip=%s: %v", ip, err)
		h.emit(h.newEvent(r, h.ipKey(r), 0, "", "CHALLENGE", "asn_error", 0))
		h.redirectToChallenge(w, r, false)
		return
	}

	entry := logEntry{
		Time:   time.Now(),
		IP:     ip.String(),
		ASN:    rec.ASN,
		Org:    rec.Org,
		Method: r.Method,
		Host:   r.Host,
		Path:   r.URL.Path,
		UA:     r.UserAgent(),
	}

	if h.asnDB.IsAllowed(rec.ASN) {
		entry.Action = "ALLOW"
		entry.Reason = "allowlist"
		entry.log()
		h.emit(h.newEvent(r, entry.IP, entry.ASN, entry.Org, "ALLOW", "allowlist", 0))
		h.proxyThrough(w, r)
		return
	}

	if h.asnDB.IsBlocked(rec.ASN) {
		entry.Action = "BLOCK"
		entry.Reason = "blocked ASN"
		entry.log()
		h.emit(h.newEvent(r, entry.IP, entry.ASN, entry.Org, "BLOCK", "blocked_asn", 0))
		h.serveBlocked(w, r)
		return
	}

	// Known bad IPs: on enough public blacklists, refused; on any, the
	// Prism puzzle (badIPFloor below). Checked after the trusted-network
	// and verified-bot passes, which vouch for the address more directly
	// than a blacklist accuses it.
	badLists, badAct := h.badIPs.Check(ip)
	if badAct == badip.Block {
		entry.Action = "BLOCK"
		entry.Reason = "bad_ip_blocked"
		entry.log()
		h.emit(h.newEvent(r, entry.IP, entry.ASN, entry.Org, "BLOCK", "bad_ip_blocked", 0))
		h.serveBlocked(w, r)
		return
	}

	if api != nil {
		h.serveAPI(w, r, api, entry)
		return
	}

	isDatacenter := rec.Datacenter
	ipKey := h.ipKey(r)
	reputationFloor := h.reputation.Floor(ipKey, rec.ASN, isDatacenter)
	// Captured here, before any later Record() call in this request (e.g. the
	// HighRequestScore recording below) can change it — ev.Pressure must
	// reflect the same pressure snapshot that produced reputationFloor, or
	// the dashboard shows two numbers that don't agree with each other.
	capturedPressure := h.reputation.IPPressure(ipKey)

	// A non-document request (XHR, fetch, an API call) cannot be served an
	// HTML interstitial — the client will never run the JavaScript on it, so
	// there is nothing to gain by trying, and the correct failure is a plain
	// 403 rather than an HTML body it cannot parse as the response it wanted.
	// This is also why Issued (below) is document-navigation-only: an XHR
	// that never got a real interstitial should not count as "unanswered."
	isDoc := isDocumentNavigation(r)
	isPrefetch := r.Header.Get("Sec-Purpose") == "prefetch"
	if !isDoc {
		entry.Action = "BLOCK"
		entry.Reason = "non_document_uncleared"
		entry.log()
		h.emit(h.newEvent(r, entry.IP, entry.ASN, entry.Org, "BLOCK", "non_document_uncleared", 0))
		http.Error(w, "clearance required", http.StatusForbidden)
		return
	}

	reqScore, reqReasons := reflexRequestScore(r, h.cfg.Hardening.ExploitPaths)
	// Saved for the Lumen challenge, which is issued on a later request
	// that no longer has this navigation's headers to score.
	h.escalations.RequireLumen(ipKey, reqScore, escalationTTL)
	signalTier := requestScoreTier(reqScore, h.cfg.Hardening.RequestScore)
	if signalTier >= tier.SingleClick {
		h.reputation.Record(ipKey, rec.ASN, reputation.HighRequestScore)
	}
	asnFloor := tier.Pass
	if isDatacenter {
		asnFloor = tier.SingleClick
	}
	badIPFloor := tier.Pass
	if badAct == badip.Challenge {
		badIPFloor = tier.Prism
	}
	// A challenge rule from rules.yaml is one more floor. It never lowers the
	// tier, and it only got this far because the client has no clearance.
	rFloor := ruleFloor(r)
	// The under-attack switch (dashboard) is one more, for everyone who got
	// this far: no clearance, not a verified bot, allow rule or api route.
	uaFloor := h.underAttack.Floor()
	effTier := tier.Max(tier.Max(tier.Max(tier.Max(tier.Max(signalTier, asnFloor), reputationFloor), badIPFloor), rFloor), uaFloor)
	reason := dispatchReason(effTier, isDatacenter, signalTier, asnFloor, reputationFloor)
	if badIPFloor == effTier && reputationFloor < effTier && signalTier < effTier {
		reason = "bad_ip"
		reqReasons = append(reqReasons, "bad_ip:"+strconv.Itoa(badLists))
	}
	ruleID := ""
	if rFloor == effTier && rFloor > tier.Pass && reputationFloor < effTier && signalTier < effTier && badIPFloor < effTier {
		reason = "rule_challenge"
		ruleID = ruleResultOf(r).hit.ID
	}
	if uaFloor == effTier && uaFloor > tier.Pass && rFloor < effTier && reputationFloor < effTier && signalTier < effTier && badIPFloor < effTier {
		reason = "under_attack"
	}

	prior := 0
	if !isPrefetch {
		if prior = h.offenders.Issued(ipKey); prior > 0 {
			h.reputation.Record(ipKey, rec.ASN, reputation.ChallengeUnanswered)
		}
	}

	// The Lumen level this client's challenge will be scored at, for the
	// dashboard's level spread — every challenged client has one, including
	// those that never answer.
	lumenScore, _ := lumen.Score(h.lumenInputs(ipKey, rec.ASN, isDatacenter, reqScore, prior))
	lumenLevel := max(lumen.LevelFor(lumenScore), lumen.Level(h.escalations.LumenDemand(ipKey)))
	if effTier == tier.Prism {
		lumenLevel = max(lumenLevel, lumenPrismFloor)
	}
	r = withLumenInfo(r, lumenInfo{level: int(lumenLevel), dispatch: true})

	entry.Action = "CHALLENGE"
	entry.Reason = reason
	entry.log()
	ev := h.newEvent(r, entry.IP, entry.ASN, entry.Org, "CHALLENGE", reason, reqScore)
	ev.Reasons = reqReasons
	ev.Pressure = capturedPressure
	ev.TierFloor = int(reputationFloor)
	ev.Tier = int(effTier)
	ev.Rule = ruleID
	h.emit(ev)

	target := ""
	switch effTier {
	case tier.Prism:
		h.escalations.Require(ipKey, tier.Prism, escalationTTL)
		target = withVerdict(r, h.prismPath+"?return="+url.QueryEscape(r.URL.RequestURI()))
	case tier.SingleClick:
		h.escalations.Require(ipKey, tier.SingleClick, escalationTTL)
		h.redirectToChallenge(w, r, true)
		return
	case tier.LumenAuto:
		h.escalations.Require(ipKey, tier.LumenAuto, escalationTTL)
		h.redirectToChallenge(w, r, false)
		return
	default:
		// Unknown ASN, unremarkable request: show the checking interstitial
		// before serving any real content. The page runs behavioral analysis
		// and POSTs results to /loupe/pulse/verify.
		target = withVerdict(r, h.pulsePath+"?return="+url.QueryEscape(r.URL.RequestURI()))
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

type pulseData struct {
	Proof                 proof.ClientSpec
	ProofJS               template.JS
	FingerprintJS         template.JS
	ProbeResultPath       string
	ReturnURL             string
	ChallengePath         string
	NoJSPath              string
	AutomationArtifactsJS template.JS
	NativeFnNamesJS       template.JS
	Footer                footerData
	Lang                  string
	T                     map[string]template.HTML
}

func (h *Handler) servePulse(w http.ResponseWriter, r *http.Request) {
	returnURL := safeReturnURL(r.URL.Query().Get("return"))
	ipKey := h.ipKey(r)
	lp := h.lumenParams(r, ipKey, true)
	sp, err := h.proofs.Issue(ipKey, proof.KindPulse, pulseSignalFields, pulseProofTTL, proof.Options{Lumen: &lp})
	if err != nil {
		log.Printf("proof issue error: %v", err)
		w.Header().Set("Retry-After", "10")
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	h.cookies.IssueProbe(w, r)
	loc := negotiateLocale(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.pulseTmpl.Execute(w, pulseData{
		Proof:                 sp.Client(),
		ProofJS:               h.proofJS,
		FingerprintJS:         h.fingerprintJS,
		ProbeResultPath:       h.pulseResultPath,
		ReturnURL:             returnURL,
		ChallengePath:         h.cfg.ChallengePath,
		NoJSPath:              h.noJSPath,
		AutomationArtifactsJS: h.automationArtifactsJS,
		NativeFnNamesJS:       h.nativeFnNamesJS,
		Footer:                h.footer(r, true),
		Lang:                  loc.Lang,
		T:                     loc.T,
	}); err != nil {
		log.Printf("checking template error: %v", err)
	}
}

func (h *Handler) servePulseResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ipKey := h.ipKey(r)
	returnURL := safeReturnURL(r.FormValue("return"))

	// The challenge is spent here whatever happens next, so a token can be
	// redeemed exactly once.
	sp, ok := h.proofs.Consume(r.FormValue("token"), ipKey, proof.KindPulse)
	if !ok {
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}
	elapsed := time.Since(sp.Issued)
	h.offenders.Answered(ipKey)

	// Primary no-cookies detection: the probe cookie set alongside
	// this interstitial (servePulse) should have returned with this
	// same-origin POST. Its absence means this client rejects cookies
	// outright — issuing clearance would only start the infinite redirect
	// loop, so redirect to the explanation page
	// instead of scoring signals that no longer matter. Checked before any
	// ASN lookup or reputation call, both because those are pointless here
	// and because a browser setting must never cost reputation pressure.
	if !h.cookies.HasProbe(r) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"action": "no_cookies",
			"url":    withVerdict(r, h.noCookiesPath+"?return="+url.QueryEscape(returnURL)),
		})
		return
	}

	pulseASN, _, _ := h.clientASN(r)

	// A blob this challenge's seal didn't produce was never generated by
	// the page's script: the canned replay that proof-of-execution stops.
	// That costs a failed-verification's pressure and a manual challenge,
	// never a block.
	signals, err := sp.Unseal(r.FormValue("sealed"))
	if err != nil {
		h.pulseFailedAnswer(w, r, "proof_unsealable", returnURL, pulseASN)
		return
	}

	// The page solves Lumen alongside its signal collection; like an
	// unsealable blob, a missing or wrong answer means the page's script did
	// not do its work.
	lres, r := h.checkLumen(r, sp, signals, elapsed)
	if lres.busy {
		lumenBusy(w)
		return
	}
	if lres.failure != "" {
		h.pulseFailedAnswer(w, r, lres.failure, returnURL, pulseASN)
		return
	}

	// A fingerprint the client randomises or blocks can't verify anything:
	// send it to the explanation page before its unstable hashes reach the
	// cluster tracker. Conclusive automation still takes precedence.
	fpHashes := fingerprintHashes(signals["fp"])
	if reason := unverifiableReadout(signals["fp"], r); reason != "" && !isConclusiveAutomation(signals) {
		h.unverifiableAnswer(w, r, reason, fpHashes, returnURL)
		return
	}

	// Instant block on conclusive automation proof (webdriver or a known
	// automation-tooling property) — redirect to manual challenge.
	cluster, clusterReasons := h.observeCluster(r, signals["fp"], fpHashes, pulseASN)

	if isConclusiveAutomation(signals) {
		reason := conclusiveAutomationReason(signals)
		log.Printf("BLOCK %s ip=%s ua=%q", reason, ipKey, r.UserAgent())
		ev := h.newEvent(r, ipKey, 0, "", "BLOCK", reason, 0)
		ev.FP = fpHashes
		h.emit(ev)
		h.reputation.Record(ipKey, pulseASN, reputation.Webdriver)
		h.reputation.RecordDevice(cluster.device, reputation.Webdriver)
		h.reputation.RecordBuild(cluster.build, reputation.BuildConclusive)
		h.escalations.Require(ipKey, tier.SingleClick, escalationTTL)
		h.demandLumen(ipKey, 2*scoreBlock)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"action": "challenge",
			"url":    withVerdict(r, h.cfg.ChallengePath+"?return="+url.QueryEscape(returnURL)+"&m=1"),
		})
		return
	}

	score, reasons := reflexProbeScore(signals, r.UserAgent())
	proofScore, proofReasons := reflexProofScore(sp, signals, elapsed)
	score += proofScore
	reasons = append(reasons, proofReasons...)
	fpScore, fpReasons := reflexFingerprintScore(signals["fp"], r)
	score += fpScore
	reasons = append(reasons, fpReasons...)
	reasons = append(reasons, clusterReasons...)
	if lres.shadow != "" {
		reasons = append(reasons, lres.shadow)
	}

	// The score picks a tier; the cluster keys' reputation can raise it,
	// never lower it.
	pulseTier := tier.Pulse
	switch {
	case score >= scoreBlock:
		pulseTier = tier.SingleClick
	case score >= scoreSuspicious:
		pulseTier = tier.LumenAuto
	}
	if floor := h.reputation.ClientFloor(cluster.device, cluster.build); floor > pulseTier {
		pulseTier = floor
		reasons = append(reasons, "cluster_floor:"+floor.String())
	}
	// A client already sent to Prism (listed, or escalated) can't collect
	// an easier clearance by answering the silent check instead.
	if why := h.prismRequired(r, ipKey); why != "" && pulseTier < tier.Prism {
		pulseTier = tier.Prism
		reasons = append(reasons, why)
	}
	logCtx := fmt.Sprintf("ip=%s score=%d reasons=%v ua=%q", ipKey, score, reasons, r.UserAgent())

	w.Header().Set("Content-Type", "application/json")

	switch pulseTier {
	case tier.Pulse:
		log.Printf("PASS probe %s", logCtx)
		ev := h.newEvent(r, ipKey, 0, "", "PASS", "pulse_pass", score)
		ev.Reasons = reasons
		ev.FP = fpHashes
		h.emit(ev)
		h.reputation.Record(ipKey, pulseASN, reputation.CleanPass)
		h.reputation.RecordDevice(cluster.device, reputation.CleanPass)
		profileHash := computeProfileHashFromSignals(signals, []byte(h.cfg.HMACSecret))
		h.cookies.IssueWithProfile(w, ipKey, r, profileHash)
		h.offenders.IncrAnsweredNoClearance(ipKey)
		json.NewEncoder(w).Encode(map[string]string{"action": "pass", "url": returnURL}) //nolint:errcheck

	case tier.LumenAuto:
		log.Printf("CHALLENGE probe_suspicious %s", logCtx)
		ev := h.newEvent(r, ipKey, 0, "", "CHALLENGE", "pulse_suspicious", score)
		ev.Reasons = reasons
		ev.FP = fpHashes
		h.emit(ev)
		h.escalations.Require(ipKey, tier.LumenAuto, escalationTTL)
		h.demandLumen(ipKey, score)
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"action": "challenge",
			"url":    withVerdict(r, h.cfg.ChallengePath+"?return="+url.QueryEscape(returnURL)),
		})

	case tier.SingleClick:
		log.Printf("CHALLENGE probe_manual %s", logCtx)
		ev := h.newEvent(r, ipKey, 0, "", "CHALLENGE", "pulse_manual", score)
		ev.Reasons = reasons
		ev.FP = fpHashes
		h.emit(ev)
		h.escalations.Require(ipKey, tier.SingleClick, escalationTTL)
		h.demandLumen(ipKey, score)
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"action": "challenge",
			"url":    withVerdict(r, h.cfg.ChallengePath+"?return="+url.QueryEscape(returnURL)+"&m=1"),
		})

	default: // tier.Prism, reachable only through a cluster floor
		log.Printf("CHALLENGE probe_prism %s", logCtx)
		ev := h.newEvent(r, ipKey, 0, "", "CHALLENGE", "pulse_prism", score)
		ev.Reasons = reasons
		ev.FP = fpHashes
		h.emit(ev)
		h.escalations.Require(ipKey, tier.Prism, escalationTTL)
		h.demandLumen(ipKey, score)
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"action": "challenge",
			"url":    withVerdict(r, h.prismPath+"?return="+url.QueryEscape(returnURL)),
		})
	}
}

func (h *Handler) ipKey(r *http.Request) string {
	return clientKey(h.realIP(r))
}

func (h *Handler) redirectToChallenge(w http.ResponseWriter, r *http.Request, forceManual bool) {
	returnURL := r.URL.RequestURI()
	target := withVerdict(r, h.cfg.ChallengePath+"?return="+url.QueryEscape(returnURL))
	if forceManual {
		target += "&m=1"
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

func (h *Handler) serveBlocked(w http.ResponseWriter, r *http.Request) {
	loc := negotiateLocale(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	data := struct {
		Lang   string
		T      map[string]template.HTML
		Footer footerData
	}{loc.Lang, loc.T, h.footer(r, false)}
	if err := h.blockedTpl.Execute(w, data); err != nil {
		log.Printf("blocked template error: %v", err)
	}
}

// serveRateLimited answers 429 with Retry-After. A browser navigating to a
// page gets a page saying so, with a countdown; anything else (assets, API
// calls, tools) gets the plain text.
func (h *Handler) serveRateLimited(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	secs := max(1, int(math.Ceil(retryAfter.Seconds())))
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	if !isDocumentNavigation(r) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	loc := negotiateLocale(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusTooManyRequests)
	wait := strings.Replace(string(loc.T["ratelimited_wait"]), "{n}", `<span id="n">`+strconv.Itoa(secs)+`</span>`, 1)
	data := struct {
		Lang   string
		T      map[string]template.HTML
		Wait   template.HTML
		Footer footerData
	}{loc.Lang, loc.T, template.HTML(wait), h.footer(r, false)}
	if err := h.rateLimitedTpl.Execute(w, data); err != nil {
		log.Printf("rate-limited template error: %v", err)
	}
}

func (h *Handler) serveChallengePage(w http.ResponseWriter, r *http.Request) {
	returnURL := safeReturnURL(r.URL.Query().Get("return"))
	_, _, isDatacenter := h.clientASN(r)
	forceManual := ""
	if r.URL.Query().Get("m") == "1" ||
		requiresSingleClick(isDatacenter, h.escalations.Level(h.ipKey(r))) {
		forceManual = "1"
	}
	loc := negotiateLocale(w, r)
	data := map[string]interface{}{
		"Lang":          loc.Lang,
		"T":             loc.T,
		"ProofJS":       h.proofJS,
		"FingerprintJS": h.fingerprintJS,
		"ReturnURL":     returnURL,
		"ChallengeURL":  h.lumenPath,
		"VerifyURL":     h.cfg.VerifyPath,
		"ForceManual":   forceManual,
		"NoJSPath":      h.noJSPath,
		"Footer":        h.footer(r, true),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.Execute(w, data); err != nil {
		log.Printf("template error: %v", err)
	}
}

func (h *Handler) serveLumenChallenge(w http.ResponseWriter, r *http.Request) {
	key := h.ipKey(r)

	// The "m" query parameter is client-supplied, so it may only raise the
	// difficulty. The authoritative sources are the ASN classification and the
	// escalation the server recorded earlier.
	_, _, isDatacenter := h.clientASN(r)
	manual := r.URL.Query().Get("m") == "1" ||
		requiresSingleClick(isDatacenter, h.escalations.Level(key))

	// Fetched when the visitor starts (or clicks), so the challenge doesn't
	// go stale while a challenge tab sits idle.
	lp := h.lumenParams(r, key, false)
	sp, err := h.proofs.Issue(key, proof.KindChallenge, challengeSignalFields, challengeProofTTL, proof.Options{Lumen: &lp, Manual: manual})
	if err != nil {
		log.Printf("proof issue error: %v", err)
		w.Header().Set("Retry-After", "10")
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(sp.Client()) //nolint:errcheck
}

func (h *Handler) serveVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ipKey := h.ipKey(r)
	verifyASN, verifyOrg, isDatacenter := h.clientASN(r)

	// Honeypot: hidden off-screen field. Any non-empty value is a bot.
	if hp := r.FormValue("website"); hp != "" {
		log.Printf("BLOCK honeypot_triggered ip=%s ua=%q", ipKey, r.UserAgent())
		h.emit(h.newEvent(r, ipKey, 0, "", "BLOCK", "honeypot_triggered", 0))
		h.offenders.Fail(ipKey)
		h.reputation.Record(ipKey, verifyASN, reputation.Honeypot)
		h.serveBlocked(w, r)
		return
	}

	returnURL := safeReturnURL(r.FormValue("return"))

	// Proof of execution: the challenge is spent here whatever happens
	// next. Missing, replayed, or unsealable answers fail exactly like a
	// missing Lumen answer — the page's script always sends both.
	sp, ok := h.proofs.Consume(r.FormValue("proof"), ipKey, proof.KindChallenge)
	var signals map[string]interface{}
	var unsealErr error
	if ok {
		signals, unsealErr = sp.Unseal(r.FormValue("sealed"))
	}
	if !ok || unsealErr != nil {
		reason := "no_proof"
		if ok {
			reason = "proof_unsealable"
		}
		log.Printf("CHALLENGE FAIL %s ip=%s ua=%q", reason, ipKey, r.UserAgent())
		h.emit(h.newEvent(r, ipKey, 0, "", "FAIL", reason, 0))
		h.offenders.Fail(ipKey)
		h.reputation.Record(ipKey, verifyASN, reputation.VerifyFailure)
		http.Error(w, "challenge required", http.StatusForbidden)
		return
	}

	fpHashes := fingerprintHashes(signals["fp"])
	cluster, clusterReasons := h.observeCluster(r, signals["fp"], fpHashes, verifyASN)

	// Webdriver is an instant block — no Lumen check needed.
	if boolVal(signals, "webdriver") {
		log.Printf("BLOCK webdriver ip=%s ua=%q", ipKey, r.UserAgent())
		h.emit(h.newEvent(r, ipKey, 0, "", "BLOCK", "webdriver", 0))
		h.offenders.Fail(ipKey)
		h.reputation.Record(ipKey, verifyASN, reputation.Webdriver)
		h.reputation.RecordDevice(cluster.device, reputation.Webdriver)
		h.reputation.RecordBuild(cluster.build, reputation.BuildConclusive)
		h.serveBlocked(w, r)
		return
	}

	// Verify Lumen (the proof challenge is already IP-bound and single-use).
	lres, r := h.checkLumen(r, sp, signals, time.Since(sp.Issued))
	if lres.busy {
		lumenBusy(w)
		return
	}
	if lres.failure != "" {
		log.Printf("CHALLENGE FAIL %s ip=%s ua=%q", lres.failure, ipKey, r.UserAgent())
		h.emit(h.newEvent(r, ipKey, 0, "", "FAIL", lres.failure, 0))
		h.offenders.Fail(ipKey)
		h.reputation.Record(ipKey, verifyASN, reputation.VerifyFailure)
		h.reputation.RecordDevice(cluster.device, reputation.VerifyFailure)
		http.Error(w, "challenge failed", http.StatusForbidden)
		return
	}
	// The challenge was issued for the single-click flow: server state,
	// which the client can't add or strip.
	wasSingleClick := sp.Manual
	// A Lumen answer that does the work proves this client ran the page's
	// JavaScript and answered — recorded before scoring, since answering at
	// all (not answering correctly) is the property being measured here.
	h.offenders.Answered(ipKey)

	// Re-derive whether this IP requires a manual challenge (server-authoritative).
	requiresSingleClick := requiresSingleClick(isDatacenter, h.escalations.Level(ipKey))

	// Datacenter IPs must submit a manual-type challenge. If they obtained an
	// auto challenge instead, its spec isn't Manual so wasSingleClick is false.
	if requiresSingleClick && !wasSingleClick {
		log.Printf("CHALLENGE manual_required ip=%s ua=%q", ipKey, r.UserAgent())
		h.emit(h.newEvent(r, ipKey, verifyASN, verifyOrg, "CHALLENGE", "manual_required", 0))
		target := withVerdict(r, h.cfg.ChallengePath+"?return="+url.QueryEscape(returnURL)+"&m=1")
		w.Header().Set("Cache-Control", "no-store")
		h.verifyRedirect(w, r, target, "redirect")
		return
	}

	// Likewise a client already sent to Prism can't trade it for the click
	// challenge — whose pass would also clear the escalation. Not a
	// failure: the answer was fine, just for the wrong challenge, and the
	// address may be shared.
	if why := h.prismRequired(r, ipKey); why != "" {
		log.Printf("CHALLENGE prism_required %s ip=%s ua=%q", why, ipKey, r.UserAgent())
		ev := h.newEvent(r, ipKey, verifyASN, verifyOrg, "CHALLENGE", "prism_required", 0)
		ev.Reasons = []string{why}
		h.emit(ev)
		target := withVerdict(r, h.prismPath+"?return="+url.QueryEscape(returnURL))
		w.Header().Set("Cache-Control", "no-store")
		h.verifyRedirect(w, r, target, "redirect")
		return
	}

	if reason := unverifiableReadout(signals["fp"], r); reason != "" && !isConclusiveAutomation(signals) {
		h.unverifiableAnswer(w, r, reason, fpHashes, returnURL)
		return
	}

	// Score behavioral signals.
	score, reasons := reflexScore(signals, r.UserAgent(), wasSingleClick, requiresSingleClick)
	proofScore, proofReasons := reflexProofScore(sp, signals, 0)
	score += proofScore
	reasons = append(reasons, proofReasons...)
	fpScore, fpReasons := reflexFingerprintScore(signals["fp"], r)
	score += fpScore
	reasons = append(reasons, fpReasons...)
	reasons = append(reasons, clusterReasons...)
	if lres.shadow != "" {
		reasons = append(reasons, lres.shadow)
	}

	// The cluster keys' reputation can raise this answer's outcome: a Prism
	// floor escalates like a high score, a SingleClick
	// floor forces the manual flow on an auto answer.
	switch floor := h.reputation.ClientFloor(cluster.device, cluster.build); {
	case floor >= tier.Prism && score < scoreBlock:
		score = scoreBlock
		reasons = append(reasons, "cluster_floor:"+floor.String())
	case floor >= tier.SingleClick && !wasSingleClick && score < scoreSuspicious:
		score = scoreSuspicious
		reasons = append(reasons, "cluster_floor:"+floor.String())
	}
	logCtx := fmt.Sprintf("ip=%s score=%d reasons=%v ua=%q", ipKey, score, reasons, r.UserAgent())

	if score >= scoreBlock {
		log.Printf("ESCALATE prism %s", logCtx)
		ev := h.newEvent(r, ipKey, verifyASN, verifyOrg, "CHALLENGE", "escalated_to_prism", score)
		ev.Reasons = reasons
		ev.FP = fpHashes
		h.emit(ev)
		h.reputation.Record(ipKey, verifyASN, reputation.VerifyFailure)
		h.reputation.RecordDevice(cluster.device, reputation.VerifyFailure)
		h.escalations.Require(ipKey, tier.Prism, escalationTTL)
		h.demandLumen(ipKey, score)
		target := withVerdict(r, h.prismPath+"?return="+url.QueryEscape(returnURL))
		w.Header().Set("Cache-Control", "no-store")
		h.verifyRedirect(w, r, target, "redirect")
		return
	}

	// Suspicious on an auto challenge → escalate to a manual challenge.
	// On the next attempt the challenge will be Manual (wasSingleClick=true), so this
	// branch is skipped and they pass as suspicious.
	if score >= scoreSuspicious && !wasSingleClick {
		log.Printf("ESCALATE suspicious_auto %s", logCtx)
		ev := h.newEvent(r, ipKey, verifyASN, verifyOrg, "CHALLENGE", "escalated_to_manual", score)
		ev.Reasons = reasons
		ev.FP = fpHashes
		h.emit(ev)
		h.escalations.Require(ipKey, tier.SingleClick, escalationTTL)
		h.demandLumen(ipKey, score)
		target := withVerdict(r, h.cfg.ChallengePath+"?return="+url.QueryEscape(returnURL)+"&m=1")
		h.verifyRedirect(w, r, target, "redirect")
		return
	}

	// Suspicious on a manual challenge that cost less than this answer
	// demands → one more manual challenge at the demanded level before the
	// pass. Shadow mode only records it.
	if score >= scoreSuspicious && h.lumenFollowup(sp, score) {
		if h.cfg.Lumen.Enforce {
			log.Printf("ESCALATE lumen_followup %s", logCtx)
			ev := h.newEvent(r, ipKey, verifyASN, verifyOrg, "CHALLENGE", "lumen_followup", score)
			ev.Reasons = reasons
			ev.FP = fpHashes
			h.emit(ev)
			h.demandLumen(ipKey, score)
			target := withVerdict(r, h.cfg.ChallengePath+"?return="+url.QueryEscape(returnURL)+"&m=1")
			h.verifyRedirect(w, r, target, "redirect")
			return
		}
		reasons = append(reasons, "lumen_followup")
	}

	if score >= scoreSuspicious {
		log.Printf("PASS suspicious %s", logCtx)
		ev := h.newEvent(r, ipKey, verifyASN, verifyOrg, "PASS", "suspicious", score)
		ev.Reasons = reasons
		ev.FP = fpHashes
		h.emit(ev)
	} else {
		log.Printf("PASS %s", logCtx)
		ev := h.newEvent(r, ipKey, verifyASN, verifyOrg, "PASS", "", score)
		ev.Reasons = reasons
		ev.FP = fpHashes
		h.emit(ev)
		h.reputation.Record(ipKey, verifyASN, reputation.CleanPass)
		h.reputation.RecordDevice(cluster.device, reputation.CleanPass)
	}
	h.offenders.Success(ipKey)

	profileHash := computeProfileHashFromSignals(signals, []byte(h.cfg.HMACSecret))
	h.escalations.Clear(ipKey)
	h.cookies.IssueWithProfile(w, ipKey, r, profileHash)
	h.offenders.IncrAnsweredNoClearance(ipKey)
	h.verifyRedirect(w, r, returnURL, "pass")
}

// verifyRedirect sends serveVerify's outcome to target. The challenge page
// POSTs with fetch and asks for JSON (Accept: application/json) so it can tell
// a real pass ("pass": clearance cookie issued, target is the site) from a
// further challenge ("redirect") before navigating — a 302 would hide that
// from it. Any other client, e.g. a plain form POST, gets the usual 302.
// unverifiableAnswer logs an answer whose fingerprint readouts can't be
// used (see unverifiableReadout) and sends the page to the explanation.
// Like the other unverifiable cases it costs no pressure and grants
// nothing; the client is back to an ordinary challenge once the setting is
// off.
func (h *Handler) unverifiableAnswer(w http.ResponseWriter, r *http.Request, reason string, fpHashes map[string]string, returnURL string) {
	log.Printf("BLOCK %s ip=%s ua=%q", reason, h.ipKey(r), r.UserAgent())
	ev := h.newEvent(r, h.ipKey(r), 0, "", "BLOCK", reason, 0)
	ev.FP = fpHashes
	h.emit(ev)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"action": "unverifiable",
		"url":    withVerdict(r, h.unverifiedPath+"?return="+url.QueryEscape(returnURL)),
	})
}

// parsePage parses one of Loupe's embedded pages together with the
// shared partials it renders: footer.html ({{template "footer"}}) and
// wordmark.html ({{template "wordmark"}}).
func parsePage(name, file string) (*template.Template, error) {
	page, err := staticFiles.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	t, err := template.New(name).Parse(string(page))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	for _, partial := range []string{"footer.html", "wordmark.html"} {
		b, err := staticFiles.ReadFile(partial)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", partial, err)
		}
		if _, err := t.Parse(string(b)); err != nil {
			return nil, fmt.Errorf("parse %s: %w", partial, err)
		}
	}
	return t, nil
}

func (h *Handler) verifyRedirect(w http.ResponseWriter, r *http.Request, target, action string) {
	if !strings.Contains(r.Header.Get("Accept"), "application/json") {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{"action": action, "url": target}) //nolint:errcheck
}

// requestScheme is the scheme the visitor used: "https" or "http".
func requestScheme(r *http.Request) string {
	if cookie.IsHTTPS(r) {
		return "https"
	}
	return "http"
}

func (h *Handler) proxyThrough(w http.ResponseWriter, r *http.Request) {
	if ip := h.realIP(r); ip != nil {
		r.Header.Set("X-Real-IP", ip.String())
	}
	h.proxy.ServeHTTP(w, r)
}

func (h *Handler) emit(e admin.Event) {
	if h.store != nil {
		h.store.Add(e)
	}
}

// emitRolled logs e through the rollups (see rollup.go) under k.
func (h *Handler) emitRolled(k rollupKey, e admin.Event, notable bool) {
	if h.rollups == nil {
		h.emit(e)
		return
	}
	h.rollups.add(k, e, notable)
}

// emitLoggedAllow records a request that skips every check (public files,
// fonts) when a log-only rule matched it, so such rules show up there too.
// Without a log-only match nothing is recorded, as before.
func (h *Handler) emitLoggedAllow(r *http.Request, reason string) {
	if len(ruleResultOf(r).logged) == 0 {
		return
	}
	key := h.ipKey(r)
	h.emitRolled(rollupKey{"ALLOW", reason, key, r.Host, r.UserAgent(), loggedRules(r)},
		h.newEvent(r, key, 0, "", "ALLOW", reason, 0), isDocumentNavigation(r))
}

func (h *Handler) newEvent(r *http.Request, ip string, asnNum uint, org, action, reason string, score int) admin.Event {
	// Most verdicts are reached before (or without) ServeHTTP's ASN lookup,
	// so callers often have no network to pass; look it up here so every
	// event shows one, with the country and what the published lists say.
	nw := h.clientNet(r)
	if asnNum == 0 {
		asnNum, org = nw.ASN, nw.Org
	}
	e := admin.Event{
		Action: action,
		IP:     ip,
		ASN:    asnNum,
		Org:    org,
		Method: r.Method,
		Host:   r.Host,
		Path:   r.URL.Path,
		UA:     r.UserAgent(),
		Reason: reason,
		Score:  score,
		VID:    verdictID(r),

		Country:    nw.Country,
		NetType:    nw.Category,
		Classes:    nw.Classes,
		Provider:   nw.Provider,
		Datacenter: nw.Datacenter,
	}
	if d, ok := r.Context().Value(botClaimKey{}).(bots.Decision); ok && d.Bot != nil {
		e.Bot, e.BotStatus = d.Bot.ID, d.Status()
	}
	e.BadIP = h.badIPs.Lists(h.realIP(r))
	e.LoggedRules = ruleResultOf(r).logged
	if l, ok := r.Context().Value(lumenInfoKey{}).(lumenInfo); ok {
		level := l.level
		e.Lumen, e.LumenDispatch, e.LumenRate, e.LumenSpaceMs = &level, l.dispatch, l.rate, l.spaceMs
	}
	return e
}

type logEntry struct {
	Time   time.Time
	IP     string
	ASN    uint
	Org    string
	Method string
	Host   string
	Path   string
	UA     string
	Action string
	Reason string
}

func (e logEntry) log() {
	log.Printf("%-9s ip=%-15s asn=%-8d org=%-30q %s %s%s reason=%s ua=%q",
		e.Action, e.IP, e.ASN, e.Org, e.Method, e.Host, e.Path, e.Reason, e.UA)
}

var privateRanges = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fc00::/7",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		nets = append(nets, n)
	}
	return nets
}()

type botClaimKey struct{}

func (h *Handler) classifyBot(ip net.IP, ua string) bots.Decision {
	if h.bots == nil {
		return bots.Decision{}
	}
	return h.bots.Classify(ip, ua)
}

// ClientIP is the proxy.trusted resolver, which the console shares.
func (h *Handler) ClientIP() *clientip.Resolver { return h.client }

// Bots exposes the bot policy manager to the admin dashboard.
func (h *Handler) Bots() *bots.Manager { return h.bots }

// ASN returns the network database, for main to keep current.
func (h *Handler) ASN() *asn.DB { return h.asnDB }

// legacyBots carries the pre-catalog good_bots / ai_crawlers settings into
// the bots package, which migrates them the first time it creates its policy
// file so upgrading changes nothing about who gets through.
func legacyBots(cfg *config.Config) *bots.Legacy {
	l := &bots.Legacy{Block: cfg.AICrawlers.Block}
	for _, b := range append(append([]config.BotDef{}, cfg.GoodBots.Bots...), cfg.AICrawlers.Allow...) {
		l.Allow = append(l.Allow, bots.LegacyBot{Name: b.Name, UAContains: b.UAContains, ValidPTR: b.ValidPTR})
	}
	if len(l.Allow) == 0 && len(l.Block) == 0 {
		return nil
	}
	return l
}

// isPublicPath reports whether p is a public asset or crawler-facing file
// that must be servable with no Loupe checks at all — including to a
// client that has not accepted any cookie or run any JavaScript. Crawlers
// must be able to read robots.txt, sitemap.xml, and friends, or they can
// never learn the site's own rules.
func isPublicPath(p string) bool {
	if strings.Contains(p, "..") {
		return false
	}
	switch p {
	case "/favicon.ico", "/favicon.png", "/favicon.svg",
		"/apple-touch-icon.png", "/apple-touch-icon-precomposed.png",
		"/robots.txt", "/sitemap.xml", "/ads.txt", "/security.txt":
		return true
	}
	return strings.HasPrefix(p, "/.well-known/")
}

func isPrivateIP(ip net.IP) bool {
	for _, n := range privateRanges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// computeProfileHashFromSignals extracts behavioral signal buckets and delegates
// to cookie.ProfileHash. Returns "" when signals is nil.
func computeProfileHashFromSignals(signals map[string]interface{}, secret []byte) string {
	if signals == nil {
		return ""
	}
	jitter := numVal(signals, "mouseJitter")
	rafVar := numVal(signals, "rafVariance")
	webgl := strVal(signals, "webglRenderer")
	scrollObs := numVal(signals, "scrollCount") > 0
	return cookie.ProfileHash(secret, jitter, rafVar, webgl, scrollObs)
}
