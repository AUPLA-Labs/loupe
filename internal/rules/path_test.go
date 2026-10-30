package rules

import "testing"

// Paths match ignoring case, in every op; User-Agents stay case-sensitive.
func TestPathMatchingIgnoresCase(t *testing.T) {
	for _, pm := range []PathMatch{{Prefix: "/Admin"}, {Exact: "/admin/LOGIN"}, {Glob: "/ADMIN/*"}, {Regex: "^/admin/log[i]n$"}} {
		s := mustCompile(t, enforce("r", Match{Paths: []PathMatch{pm}}))
		if hit, _, _ := (probe{target: "/aDmIn/Login"}).run(t, s); hit == nil {
			t.Errorf("%+v did not match /aDmIn/Login", pm)
		}
	}
	s := mustCompile(t, enforce("r", Match{UserAgents: []PathMatch{{Prefix: "Nikto"}}}))
	if hit, _, _ := (probe{ua: "nikto/2.1"}).run(t, s); hit != nil {
		t.Error("a User-Agent prefix matched ignoring case")
	}
}

// Rules match the canonical path the handler supplies, and its anomalies.
func TestRulesUseFactsPathAndAnomalies(t *testing.T) {
	s := mustCompile(t,
		enforce("admin", Match{Paths: []PathMatch{{Prefix: "/admin"}}}),
		enforce("tricks", Match{Anomalies: []string{"double_encoded"}}))
	r := newProbeRequest(probe{target: "/x/../admin"})
	e := env{}
	f := e.facts(r, "198.51.100.7")
	f.Path = "/admin"
	if hit, _ := s.Evaluate(f); hit == nil || hit.ID != "admin" {
		t.Fatalf("hit %+v, want the canonical path to match", hit)
	}
	f = e.facts(newProbeRequest(probe{target: "/ok"}), "198.51.100.7")
	f.Anomalies = []string{"null_byte", "double_encoded"}
	if hit, _ := s.Evaluate(f); hit == nil || hit.ID != "tricks" {
		t.Fatalf("hit %+v, want the anomaly rule", hit)
	}
	if _, errs := Compile([]Rule{enforce("bad", Match{Anomalies: []string{"sneaky"}})}); len(errs) != 1 {
		t.Errorf("unknown anomaly: errors %v, want one", errs)
	}
}
