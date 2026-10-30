package config

import (
	"os"
	"strings"
	"testing"
)

const sample = `# Top comment
listen: "127.0.0.1:8080"
cookie_ttl: 86400  # 24 hours

lumen:
  work: 100000   # solver cost

asn:
  blocked_asns: []
  datacenter_asns:
    - 15169   # Google LLC
    - 396982  # Google Cloud EMEA

  # trailing comment of asn
  datacenter_asns_file: "x.txt"

abuse:
  rate_limit:
    rate: 1.0
    burst: 15

reputation:
  floors: { tier2: 4, tier3: 12, tier4: 40 }
`

func TestApplyEditsPreservesEverythingElse(t *testing.T) {
	out, err := ApplyEdits([]byte(sample), []Edit{
		{Path: []string{"cookie_ttl"}, Scalar: "43200", Comment: "12 hours"},
		{Path: []string{"lumen", "work"}, Scalar: "250000"},
		{Path: []string{"abuse", "rate_limit", "rate"}, Scalar: "2.5"},
		{Path: []string{"reputation", "floors", "tier3"}, Scalar: "15"},
		{Path: []string{"asn", "blocked_asns"}, IsList: true, List: []ListItem{{Value: "64500", Comment: "Bad Net"}, {Value: "4134"}}},
		{Path: []string{"asn", "datacenter_asns"}, IsList: true, List: []ListItem{{Value: "15169", Comment: "Google LLC"}}},
		{Path: []string{"lumen", "pulse_work"}, Scalar: "30000"},
		{Path: []string{"hardening", "exploit_paths"}, IsList: true, List: []ListItem{{Value: RenderString("/wp-admin")}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{
		"# Top comment\n",
		"cookie_ttl: 43200  # 12 hours\n",
		"  work: 250000   # solver cost\n", // comment keeps its column
		"  pulse_work: 30000\n",
		"    rate: 2.5\n",
		"floors: { tier2: 4, tier3: 15, tier4: 40 }",
		"  blocked_asns:\n    - 64500  # Bad Net\n    - 4134\n  datacenter_asns:\n",
		"    - 15169  # Google LLC\n\n  # trailing comment of asn\n",
		"\nhardening:\n  exploit_paths:\n    - /wp-admin\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "396982") {
		t.Error("removed list item still present")
	}
	if _, err := LoadBytes(out); err != nil {
		t.Fatalf("edited config invalid: %v", err)
	}
}

// A config.yaml from before clearance_budget existed has abuse: but not the
// block; saving a budget from the dashboard must add it under abuse.
func TestApplyEditsAddsClearanceBudgetBlock(t *testing.T) {
	out, err := ApplyEdits([]byte(sample), []Edit{
		{Path: []string{"abuse", "clearance_budget", "doc_burst"}, Scalar: "100"},
		{Path: []string{"abuse", "clearance_budget", "all_rate"}, Scalar: "2.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := "    burst: 15\n  clearance_budget:\n    doc_burst: 100\n    all_rate: 2.5\n"; !strings.Contains(string(out), want) {
		t.Errorf("missing %q in:\n%s", want, out)
	}
	cfg, err := LoadBytes(out)
	if err != nil {
		t.Fatalf("edited config invalid: %v", err)
	}
	if b := cfg.Abuse.ClearanceBudget; b.DocBurst != 100 || b.AllRate != 2.5 || b.DocRate != 0.5 || b.AllBurst != 3000 {
		t.Errorf("budget = %+v, want edited doc_burst/all_rate and default doc_rate/all_burst", b)
	}
}

func TestApplyEditsEmptiesList(t *testing.T) {
	out, err := ApplyEdits([]byte(sample), []Edit{{Path: []string{"asn", "datacenter_asns"}, IsList: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "  datacenter_asns: []\n\n  # trailing comment of asn") {
		t.Fatalf("got:\n%s", out)
	}
}

func TestRenderString(t *testing.T) {
	for in, want := range map[string]string{"/wp-admin": "/wp-admin", "yes": `"yes"`, "a b": `"a b"`, "": `""`, "x#y": `"x#y"`} {
		if got := RenderString(in); got != want {
			t.Errorf("RenderString(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestListComments(t *testing.T) {
	c := ListComments([]byte(sample), "asn", "datacenter_asns")
	if c["15169"] != "Google LLC" || c["396982"] != "Google Cloud EMEA" {
		t.Fatalf("comments = %v", c)
	}
}

// The real config.yaml must survive a no-op edit byte for byte.
func TestApplyEditsNoOpOnRealConfig(t *testing.T) {
	src, err := os.ReadFile("../../config.yaml")
	if err != nil {
		t.Skip("no config.yaml")
	}
	out, err := ApplyEdits(src, []Edit{
		{Path: []string{"cookie_ttl"}, Scalar: "86400"},
		{Path: []string{"reputation", "floors", "tier2"}, Scalar: "4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(src) {
		t.Fatal("no-op edits changed the file")
	}
}
