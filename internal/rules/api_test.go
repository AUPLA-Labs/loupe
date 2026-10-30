package rules

import "testing"

func apiRule(id, auth string) Rule {
	return Rule{ID: id, Mode: ModeEnforce, Action: ActionAPI, API: &APIPolicy{Auth: auth},
		Match: Match{Paths: []PathMatch{{Prefix: "/api/"}}}}
}

func TestAPIRuleDoesNotEndTheSearch(t *testing.T) {
	everything := Match{Paths: []PathMatch{{Prefix: "/"}}}
	challenge := Rule{ID: "chal", Mode: ModeEnforce, Action: ActionChallenge, Tier: "prism", Match: everything}
	s := mustCompile(t, apiRule("api", APIAuthBackendHeader), apiRule("api2", APIAuthNone), challenge, enforce("block", Match{Paths: []PathMatch{{Prefix: "/api/blocked"}}}))

	hit, _, _ := probe{target: "/api/items"}.run(t, s)
	if hit == nil || hit.Action != ActionAPI || hit.ID != "api" || hit.API == nil || hit.API.Auth != APIAuthBackendHeader || hit.API.Header != "Authorization" {
		t.Fatalf("hit %+v, want the first api rule with its defaults, the challenge below skipped", hit)
	}
	hit, _, _ = probe{target: "/api/blocked"}.run(t, s)
	if hit == nil || hit.ID != "block" || hit.APIID != "api" {
		t.Fatalf("hit %+v, want the block below, carrying the api policy", hit)
	}
	hit, _, _ = probe{target: "/page"}.run(t, s)
	if hit == nil || hit.ID != "chal" || hit.API != nil {
		t.Fatalf("hit %+v, want the challenge off the api route", hit)
	}
}

func TestAPIRuleLogModeOnlyLogs(t *testing.T) {
	r := apiRule("api", APIAuthNone)
	r.Mode = ModeLog
	hit, logged, _ := probe{target: "/api/x"}.run(t, mustCompile(t, r))
	if hit != nil || len(logged) != 1 {
		t.Fatalf("hit %+v logged %v, want only logged", hit, logged)
	}
}

func TestCompileChecksAPI(t *testing.T) {
	for _, tc := range []struct {
		name  string
		r     Rule
		field string
	}{
		{"no policy", Rule{ID: "r", Action: ActionAPI, Match: Match{Methods: []string{"GET"}}}, "api"},
		{"policy on block", func() Rule {
			r := enforce("r", Match{Methods: []string{"GET"}})
			r.API = &APIPolicy{Auth: APIAuthNone}
			return r
		}(), "api"},
		{"no auth", apiRule("r", ""), "api.auth"},
		{"bad auth", apiRule("r", "jwt"), "api.auth"},
		{"bad header", func() Rule { r := apiRule("r", APIAuthBackendHeader); r.API.Header = "X Key"; return r }(), "api.header"},
		{"header with none", func() Rule { r := apiRule("r", APIAuthNone); r.API.Header = "X-Key"; return r }(), "api.header"},
		{"bad error", func() Rule { r := apiRule("r", APIAuthNone); r.API.Error = "xml"; return r }(), "api.error"},
		{"quoted realm", func() Rule { r := apiRule("r", APIAuthNone); r.API.Realm = `a"b`; return r }(), "api.realm"},
	} {
		_, errs := Compile([]Rule{tc.r})
		if len(errs) != 1 || errs[0].(*RuleError).Field != tc.field {
			t.Errorf("%s: errors %v, want one on %s", tc.name, errs, tc.field)
		}
	}
}

func TestAPIPolicyParsesAndClones(t *testing.T) {
	rs, err := Parse([]byte("rules:\n  - id: a\n    action: api\n    api: {auth: backend_header, header: x-api-key, allow_cookie: false, error: json, realm: r}\n    match: {paths: [{prefix: /api/}]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	p := rs[0].API
	if p == nil || p.CookieAllowed() || p.Error != "json" || p.Header != "x-api-key" {
		t.Fatalf("parsed %+v", p)
	}
	c := rs[0].clone()
	*c.API.AllowCookie = true
	if p.CookieAllowed() {
		t.Fatal("clone shares allow_cookie with the original")
	}
}
