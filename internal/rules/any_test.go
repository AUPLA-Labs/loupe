package rules

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The any list is what the dashboard's builder writes: groups ORed, the
// conditions inside a group ANDed, each one optionally negated.
func TestAnyGroupsParseAndEvaluate(t *testing.T) {
	rs, err := Parse([]byte(`rules:
  - id: login-or-admin
    mode: enforce
    action: block
    any:
      - all:
          - paths: [{exact: /login}]
          - methods: [POST]
      - all:
          - paths: [{prefix: /admin}]
          - ips: [203.0.113.0/24]
            not: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if !rs[0].Any[1].All[1].Not || rs[0].Any[1].All[1].IPs[0] != "203.0.113.0/24" {
		t.Fatalf("parsed %+v", rs[0].Any)
	}
	s, errs := Compile(rs)
	if errs != nil {
		t.Fatal(errs)
	}
	for _, tc := range []struct {
		p    probe
		want bool
	}{
		{probe{method: "POST", target: "/login"}, true},
		{probe{method: "GET", target: "/login"}, false}, // first group needs POST
		{probe{target: "/admin/x"}, true},               // not from 203.0.113.0/24
		{probe{target: "/admin/x", ip: "203.0.113.9"}, false},
		{probe{method: "POST", target: "/other"}, false},
	} {
		hit, _, _ := tc.p.run(t, s)
		if (hit != nil) != tc.want {
			t.Errorf("%s %s from %q: hit=%v, want %v", tc.p.method, tc.p.target, tc.p.ip, hit, tc.want)
		}
	}
}

func TestAnyCombinesWithMatchAndExcept(t *testing.T) {
	s, errs := Compile([]Rule{{
		ID: "r", Mode: ModeEnforce, Action: ActionBlock,
		Match:  Match{Methods: []string{"POST"}},
		Any:    []Group{{All: []Condition{{Match: Match{Paths: []PathMatch{{Prefix: "/a"}}}}}}},
		Except: &Match{UserAgents: []PathMatch{{Exact: "ok"}}},
	}})
	if errs != nil {
		t.Fatal(errs)
	}
	for _, tc := range []struct {
		p    probe
		want bool
	}{
		{probe{method: "POST", target: "/a"}, true},
		{probe{method: "GET", target: "/a"}, false},
		{probe{method: "POST", target: "/b"}, false},
		{probe{method: "POST", target: "/a", ua: "ok"}, false},
	} {
		if hit, _, _ := tc.p.run(t, s); (hit != nil) != tc.want {
			t.Errorf("%+v: hit=%v, want %v", tc.p, hit, tc.want)
		}
	}
}

// A negated test on a fact Loupe can't establish holds: "network is not
// AS64496" is true of an address whose network is unknown.
func TestNegatedUnknownFactHolds(t *testing.T) {
	s, errs := Compile([]Rule{{ID: "r", Mode: ModeEnforce, Action: ActionBlock,
		Any: []Group{{All: []Condition{{Match: Match{ASNs: []uint{64496}}, Not: true}}}}}})
	if errs != nil {
		t.Fatal(errs)
	}
	if hit, _, _ := (probe{}).run(t, s); hit == nil {
		t.Error("unknown network should satisfy a negated ASN condition")
	}
	if hit, _, _ := (probe{env: env{asn: 64496, asnOK: true}}).run(t, s); hit != nil {
		t.Error("AS64496 matched a rule that excludes it")
	}
}

func TestAnyValidation(t *testing.T) {
	_, errs := Compile([]Rule{{ID: "r", Action: ActionBlock, Any: []Group{
		{},
		{All: []Condition{{}, {Match: Match{Paths: []PathMatch{{Regex: "("}}}}}},
	}}})
	want := map[string]bool{"any[0].all": false, "any[1].all[0]": false, "any[1].all[1].paths[0].regex": false}
	for _, e := range errs {
		re := e.(*RuleError)
		if _, ok := want[re.Field]; ok {
			want[re.Field] = true
		} else {
			t.Errorf("unexpected error %v", e)
		}
	}
	for f, seen := range want {
		if !seen {
			t.Errorf("no error for %s", f)
		}
	}
}

func TestCloneCopiesAnyGroups(t *testing.T) {
	r := Rule{ID: "r", Any: []Group{{All: []Condition{{Match: Match{IPs: []string{"1.2.3.4"}}}}}}}
	c := r.clone()
	c.Any[0].All[0].IPs[0] = "x"
	c.Any[0].All[0].Not = true
	if r.Any[0].All[0].IPs[0] != "1.2.3.4" || r.Any[0].All[0].Not {
		t.Error("clone shares any groups with the original")
	}
}

// A rule written by the builder saves without an empty match block, and the
// file reads back to the same rule.
func TestAnySavesAndReloads(t *testing.T) {
	m := NewManager(t.TempDir() + "/rules.yaml")
	r := Rule{ID: "r", Action: ActionBlock, Any: []Group{{All: []Condition{
		{Match: Match{Paths: []PathMatch{{Prefix: "/a"}}}},
		{Match: Match{IPs: []string{"203.0.113.0/24"}}, Not: true},
	}}}}
	_, after, err := m.SaveIf([]Rule{r}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "match") {
		t.Errorf("saved an empty match block:\n%s", after)
	}
	back, err := Parse(after)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back[0].Any, r.Any) {
		t.Errorf("read back %+v, want %+v\n%s", back[0].Any, r.Any, after)
	}
}

// The dashboard sends conditions as flat JSON objects, and the save handler
// refuses unknown fields, so the embedded Match must decode field by field.
func TestConditionJSONIsFlat(t *testing.T) {
	in := `{"id":"r","action":"block","any":[{"all":[{"ips":["203.0.113.7"],"not":true}]}]}`
	var r Rule
	dec := json.NewDecoder(strings.NewReader(in))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		t.Fatal(err)
	}
	if c := r.Any[0].All[0]; !c.Not || c.IPs[0] != "203.0.113.7" {
		t.Fatalf("decoded %+v", c)
	}
	out, _ := json.Marshal(r.Any)
	if string(out) != `[{"all":[{"ips":["203.0.113.7"],"not":true}]}]` {
		t.Errorf("encoded %s", out)
	}
}
