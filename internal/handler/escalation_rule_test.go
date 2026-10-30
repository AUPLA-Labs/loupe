package handler

import (
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

func TestRequiresSingleClick(t *testing.T) {
	cases := []struct {
		name         string
		isDatacenter bool
		escalated    tier.Tier
		want         bool
	}{
		{"residential, no escalation", false, tier.Pass, false},
		{"residential, escalated to singleclick", false, tier.SingleClick, true},
		{"residential, escalated to prism", false, tier.Prism, true},
		{"residential, escalated only to lumen", false, tier.LumenAuto, false},
		{"residential, escalated only to pulse", false, tier.Pulse, false},
		{"datacenter, no escalation", true, tier.Pass, true},
		{"datacenter, escalated", true, tier.Prism, true},
		{"datacenter, escalated only to lumen", true, tier.LumenAuto, true},
	}
	for _, c := range cases {
		if got := requiresSingleClick(c.isDatacenter, c.escalated); got != c.want {
			t.Errorf("%s: requiresSingleClick(%v, %v) = %v, want %v",
				c.name, c.isDatacenter, c.escalated, got, c.want)
		}
	}
}
