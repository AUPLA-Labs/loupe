package tier

import "testing"

func TestOrdering(t *testing.T) {
	// The whole design depends on tiers being comparable with >=, so that a
	// floor can raise a tier but never lower it.
	if !(Pass < Pulse && Pulse < LumenAuto && LumenAuto < SingleClick && SingleClick < Prism) {
		t.Fatal("tiers must be strictly increasing in severity")
	}
}

func TestMax(t *testing.T) {
	cases := []struct {
		name string
		a, b Tier
		want Tier
	}{
		{"b higher", Pulse, Prism, Prism},
		{"a higher", SingleClick, LumenAuto, SingleClick},
		{"equal", Pulse, Pulse, Pulse},
		{"pass vs anything", Pass, LumenAuto, LumenAuto},
	}
	for _, c := range cases {
		if got := Max(c.a, c.b); got != c.want {
			t.Errorf("%s: Max(%v, %v) = %v, want %v", c.name, c.a, c.b, got, c.want)
		}
	}
}

func TestString(t *testing.T) {
	cases := []struct {
		in   Tier
		want string
	}{
		{Pass, "pass"},
		{Pulse, "pulse"},
		{LumenAuto, "lumen_auto"},
		{SingleClick, "singleclick"},
		{Prism, "prism"},
		{Tier(99), "tier(99)"},
	}
	for _, c := range cases {
		if got := c.in.String(); got != c.want {
			t.Errorf("Tier(%d).String() = %q, want %q", int(c.in), got, c.want)
		}
	}
}
