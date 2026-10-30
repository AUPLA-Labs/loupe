package handler

import (
	"testing"

	"github.com/AUPLA-Labs/loupe/internal/tier"
)

func TestDispatchReason(t *testing.T) {
	cases := []struct {
		name            string
		effTier         tier.Tier
		datacenter      bool
		signalTier      tier.Tier
		asnFloor        tier.Tier
		reputationFloor tier.Tier
		want            string
	}{
		{"pure datacenter, no signal, no pressure", tier.SingleClick, true, tier.Pulse, tier.SingleClick, tier.Pass, "datacenter"},
		{"datacenter but signal already at singleclick", tier.SingleClick, true, tier.SingleClick, tier.SingleClick, tier.Pass, "request_score_singleclick"},
		{"residential lumen from signal", tier.LumenAuto, false, tier.LumenAuto, tier.Pass, tier.Pass, "request_score_lumen"},
		{"residential singleclick from signal", tier.SingleClick, false, tier.SingleClick, tier.Pass, tier.Pass, "request_score_singleclick"},
		{"residential prism from signal", tier.Prism, false, tier.Prism, tier.Pass, tier.Pass, "request_score_prism"},
		{"default pulse", tier.Pulse, false, tier.Pulse, tier.Pass, tier.Pass, "pulse_check"},
		{"reputation alone raises an otherwise-clean residential request", tier.SingleClick, false, tier.Pulse, tier.Pass, tier.SingleClick, "reputation_pressure"},
		{"reputation raises above a datacenter floor", tier.Prism, true, tier.Pulse, tier.SingleClick, tier.Prism, "reputation_pressure"},
		{"reputation equals but does not exceed the signal tier — signal reason wins", tier.SingleClick, false, tier.SingleClick, tier.Pass, tier.SingleClick, "request_score_singleclick"},
	}
	for _, c := range cases {
		if got := dispatchReason(c.effTier, c.datacenter, c.signalTier, c.asnFloor, c.reputationFloor); got != c.want {
			t.Errorf("%s: dispatchReason(%v,%v,%v,%v,%v) = %q, want %q",
				c.name, c.effTier, c.datacenter, c.signalTier, c.asnFloor, c.reputationFloor, got, c.want)
		}
	}
}
