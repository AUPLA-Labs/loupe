package admin

import "testing"

func TestOrgBackfill(t *testing.T) {
	s, err := NewStore(10, "")
	if err != nil {
		t.Fatal(err)
	}
	s.Add(Event{IP: "8.8.8.8", ASN: 15169})
	s.Add(Event{IP: "1.1.1.1", ASN: 13335, Org: "Cloudflare, Inc."})
	s.Add(Event{IP: "8.8.4.4", ASN: 15169})
	s.Add(Event{IP: "10.0.0.1"})
	if got := s.ASNsWithoutOrg(); len(got) != 1 || got[0] != 15169 {
		t.Fatalf("ASNsWithoutOrg = %v", got)
	}

	s.FillOrg(15169, "Google LLC")
	for _, e := range s.Recent(10, "") {
		if e.ASN == 15169 && e.Org != "Google LLC" {
			t.Errorf("%s not filled: %q", e.IP, e.Org)
		}
		if e.ASN == 13335 && e.Org != "Cloudflare, Inc." {
			t.Errorf("existing name overwritten: %q", e.Org)
		}
	}
	if got := s.ASNsWithoutOrg(); len(got) != 0 {
		t.Errorf("ASNsWithoutOrg after fill = %v", got)
	}

	// Events added later get the name from the lookup.
	s.SetOrgLookup(func(asn uint) string {
		if asn == 64500 {
			return "Example Net"
		}
		return ""
	})
	s.Add(Event{IP: "192.0.2.1", ASN: 64500})
	s.Add(Event{IP: "192.0.2.2", ASN: 64500, Org: "Kept"})
	r := s.Recent(2, "") // oldest first
	if r[0].Org != "Example Net" || r[1].Org != "Kept" {
		t.Errorf("Add names = %q, %q", r[0].Org, r[1].Org)
	}
}
