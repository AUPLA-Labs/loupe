package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/apikeys"
)

// aplaRules is the acceptance rule set: api.auplalabs.com's routes, split
// between token routes the backend checks and open ones.
const aplaRules = `
rules:
  - id: token-signup
    mode: enforce
    action: rate_limit
    limit: {requests: 2, period: 1h}
    match: {methods: [POST], paths: [{exact: /v1/tokens}]}
  - id: no-scanners-here
    mode: enforce
    action: block
    match: {paths: [{prefix: /v1/asn/blocked}]}
  - id: asn-api
    mode: enforce
    action: api
    api:
      auth: backend_header
      realm: aupldb
      message: "missing or invalid token (terms: GET /v1/terms, token: POST /v1/tokens)"
    any:
      - all: [{paths: [{glob: "/v1/asn/*"}]}]
      - all: [{paths: [{exact: /v1/asn}]}, {methods: [POST]}]
      - all: [{paths: [{exact: /v1/asn.aupldb}]}]
  - id: open-api
    mode: enforce
    action: api
    api: {auth: none}
    match: {paths: [{exact: /healthz}, {prefix: /v1/badips}, {exact: /v1/terms}, {exact: /v1/tokens}]}
  - id: datacenter-challenge
    mode: enforce
    action: challenge
    tier: prism
    match: {paths: [{prefix: /}]}
`

// apiCall is a script's request: an HTTP client library, no browser headers.
func apiCall(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = clearanceTestIP + ":1234"
	r.Header.Set("User-Agent", "curl/8.5.0")
	r.Header.Set("Accept", "*/*")
	return r
}

func TestAPIRouteSkipsInterstitial(t *testing.T) {
	f := newRulesFixture(t, aplaRules)
	for _, path := range []string{"/healthz", "/v1/badips/meta", "/v1/terms"} {
		w := f.serve(apiCall(http.MethodGet, path))
		if w.Code != http.StatusOK {
			t.Errorf("GET %s from curl: status %d, want it proxied (auth: none)", path, w.Code)
		}
	}
	if f.backend.Load() != 3 {
		t.Fatalf("backend hits %d, want 3", f.backend.Load())
	}
	if evs := f.events("ALLOW", "api_open"); len(evs) == 0 || evs[0].Rule != "open-api" {
		t.Errorf("ALLOW api_open events = %+v, want them naming open-api", evs)
	}
	// Outside the api routes, the same client is still refused.
	if w := f.serve(apiCall(http.MethodGet, "/page")); w.Code != http.StatusForbidden {
		t.Errorf("curl on a non-api path: status %d, want 403", w.Code)
	}
}

func TestBackendHeaderModeRequiresHeaderOnly(t *testing.T) {
	f := newRulesFixture(t, aplaRules)
	w := f.serve(apiCall(http.MethodGet, "/v1/asn/1.1.1.1"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status %d, want 401", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != `Bearer realm="aupldb"` {
		t.Errorf("WWW-Authenticate = %q, want the API's own", got)
	}
	if !strings.Contains(w.Body.String(), "POST /v1/tokens") {
		t.Errorf("body %q, want the configured message", w.Body.String())
	}
	if evs := f.events("BLOCK", "api_unauthorized"); len(evs) != 1 || evs[0].Rule != "asn-api" {
		t.Errorf("BLOCK api_unauthorized events = %+v, want one naming asn-api", evs)
	}

	// Any value passes: the backend validates it.
	r := apiCall(http.MethodGet, "/v1/asn/1.1.1.1")
	r.Header.Set("Authorization", "Bearer whatever")
	if w := f.serve(r); w.Code != http.StatusOK {
		t.Fatalf("with a token: status %d, want proxied", w.Code)
	}
	r = apiCall(http.MethodPost, "/v1/asn")
	r.Header.Set("Authorization", "Bearer whatever")
	if w := f.serve(r); w.Code != http.StatusOK {
		t.Fatalf("POST /v1/asn with a token: status %d, want proxied", w.Code)
	}
	if f.backend.Load() != 2 {
		t.Errorf("backend hits %d, want 2", f.backend.Load())
	}
}

func TestAPIRouteUnauthorizedIsJSON401(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: api
    mode: enforce
    action: api
    api: {auth: backend_header, header: X-Api-Key, error: json}
    match: {paths: [{prefix: /api/}]}
`)
	w := f.serve(apiCall(http.MethodGet, "/api/items"))
	if w.Code != http.StatusUnauthorized || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, type %q, want a JSON 401", w.Code, w.Header().Get("Content-Type"))
	}
	if strings.TrimSpace(w.Body.String()) != `{"error":"clearance_required"}` {
		t.Errorf("body %q", w.Body.String())
	}
	r := apiCall(http.MethodGet, "/api/items")
	r.Header.Set("X-Api-Key", "k")
	if w := f.serve(r); w.Code != http.StatusOK {
		t.Errorf("with the configured header: status %d, want proxied", w.Code)
	}
}

func TestClearedBrowserPassesAPIRoute(t *testing.T) {
	f := newRulesFixture(t, aplaRules)
	clearance := issueClearance(t, &Handler{cookies: f.h.cookies}, chromeNav())
	r := chromeNav()
	r.URL.Path = "/v1/asn/1.1.1.1"
	r.Header.Set("Sec-Fetch-Dest", "empty")
	r.Header.Set("Sec-Fetch-Mode", "cors")
	r.Header.Set("Accept", "application/json")
	for _, c := range clearance {
		r.AddCookie(c)
	}
	if w := f.serve(r); w.Code != http.StatusOK {
		t.Fatalf("cleared SPA call without a token: status %d, want proxied", w.Code)
	}

	g := newRulesFixture(t, `
rules:
  - id: api
    mode: enforce
    action: api
    api: {auth: backend_header, allow_cookie: false}
    match: {paths: [{prefix: /api/}]}
`)
	clearance = issueClearance(t, &Handler{cookies: g.h.cookies}, chromeNav())
	r = chromeNav()
	r.URL.Path = "/api/x"
	for _, c := range clearance {
		r.AddCookie(c)
	}
	if w := g.serve(r); w.Code != http.StatusUnauthorized {
		t.Fatalf("allow_cookie: false, cookie but no header: status %d, want 401", w.Code)
	}
}

func TestPreflightPasses(t *testing.T) {
	f := newRulesFixture(t, aplaRules)
	r := chromeNav()
	r.Method = http.MethodOptions
	r.URL.Path = "/v1/asn/1.1.1.1"
	r.Header.Set("Access-Control-Request-Method", "GET")
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	if w := f.serve(r); w.Code != http.StatusOK {
		t.Fatalf("CORS preflight: status %d, want proxied", w.Code)
	}
	if len(f.events("ALLOW", "api_preflight")) != 1 {
		t.Error("no ALLOW api_preflight event")
	}
}

func TestBlockRuleStillAppliesToAPIRoute(t *testing.T) {
	f := newRulesFixture(t, aplaRules)
	r := apiCall(http.MethodGet, "/v1/asn/blocked")
	r.Header.Set("Authorization", "Bearer t")
	if w := f.serve(r); w.Code != http.StatusForbidden || f.backend.Load() != 0 {
		t.Fatalf("status %d, backend %d; a block rule above must still block", w.Code, f.backend.Load())
	}
	// Scanners are refused on api routes too.
	r = apiCall(http.MethodGet, "/healthz")
	r.Header.Set("User-Agent", "sqlmap/1.7")
	if w := f.serve(r); w.Code != http.StatusForbidden {
		t.Errorf("sqlmap on an open api route: status %d, want 403", w.Code)
	}
}

func TestAPIRateLimitStillApplies(t *testing.T) {
	f := newRulesFixture(t, aplaRules)
	for i := range 2 {
		if w := f.serve(apiCall(http.MethodPost, "/v1/tokens")); w.Code != http.StatusOK {
			t.Fatalf("signup %d: status %d, want proxied", i+1, w.Code)
		}
	}
	w := f.serve(apiCall(http.MethodPost, "/v1/tokens"))
	if w.Code != http.StatusTooManyRequests || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("3rd signup: status %d type %q, want a plain 429", w.Code, w.Header().Get("Content-Type"))
	}
}

// A rate limit that would challenge can't on an api route: it answers 429.
func TestAPIRateLimitChallengeBecomes429(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: api
    mode: enforce
    action: api
    api: {auth: none}
    match: {paths: [{prefix: /api/}]}
  - id: lim
    mode: enforce
    action: rate_limit
    tier: prism
    limit: {requests: 1, period: 1m, then: challenge}
    match: {paths: [{prefix: /api/}]}
`)
	f.serve(apiCall(http.MethodGet, "/api/a"))
	if w := f.serve(apiCall(http.MethodGet, "/api/a")); w.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", w.Code)
	}
}

func TestLoupeKeysRoute(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: keyed
    mode: enforce
    action: api
    api: {auth: loupe_keys, error: json}
    match: {paths: [{prefix: /api/}]}
`)
	plain, k, err := f.h.apiKeys.Create(apikeys.NewKey{Name: "partner", Rate: 1, Burst: 1})
	if err != nil {
		t.Fatal(err)
	}
	office, _, _ := f.h.apiKeys.Create(apikeys.NewKey{Name: "office", CIDRs: []string{"203.0.113.0/24"}})

	call := func(header, value string) *httptest.ResponseRecorder {
		r := apiCall(http.MethodGet, "/api/x")
		if header != "" {
			r.Header.Set(header, value)
		}
		return f.serve(r)
	}
	if w := call("", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no key: %d, want 401", w.Code)
	}
	if w := call("X-API-Key", "lpk_madeup"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown key: %d, want 401", w.Code)
	}
	if w := call("X-API-Key", plain); w.Code != http.StatusOK {
		t.Fatalf("valid key: %d, want proxied", w.Code)
	}
	if evs := f.events("ALLOW", "api_key"); len(evs) != 1 || len(evs[0].Reasons) != 1 || evs[0].Reasons[0] != "key:"+k.ID {
		t.Errorf("ALLOW api_key events = %+v, want one naming the key", evs)
	}
	if w := call("X-API-Key", plain); w.Code != http.StatusTooManyRequests {
		t.Fatalf("over the key's limit: %d, want 429", w.Code)
	}
	if w := call("X-API-Key", office); w.Code != http.StatusForbidden {
		t.Fatalf("key from outside its network: %d, want 403", w.Code)
	}
	if _, ok, _ := f.h.apiKeys.Revoke(k.ID); !ok {
		t.Fatal("revoke failed")
	}
	if w := call("X-API-Key", plain); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key: %d, want 401", w.Code)
	}
}

func TestLoupeKeysInAuthorizationHeader(t *testing.T) {
	f := newRulesFixture(t, `
rules:
  - id: keyed
    mode: enforce
    action: api
    api: {auth: loupe_keys, header: Authorization}
    match: {paths: [{prefix: /api/}]}
`)
	plain, _, _ := f.h.apiKeys.Create(apikeys.NewKey{Name: "a"})
	r := apiCall(http.MethodGet, "/api/x")
	r.Header.Set("Authorization", "Bearer "+plain)
	if w := f.serve(r); w.Code != http.StatusOK {
		t.Fatalf("Bearer key: %d, want proxied", w.Code)
	}
}
