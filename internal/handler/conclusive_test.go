package handler

import "testing"

func TestIsConclusiveAutomation(t *testing.T) {
	cases := []struct {
		name string
		sig  map[string]interface{}
		want bool
	}{
		{"clean", map[string]interface{}{"webdriver": false, "automationArtifact": false}, false},
		{"webdriver", map[string]interface{}{"webdriver": true}, true},
		{"artifact", map[string]interface{}{"automationArtifact": true}, true},
		{"both", map[string]interface{}{"webdriver": true, "automationArtifact": true}, true},
		{"empty map", map[string]interface{}{}, false},
	}
	for _, c := range cases {
		if got := isConclusiveAutomation(c.sig); got != c.want {
			t.Errorf("%s: isConclusiveAutomation(%v) = %v, want %v", c.name, c.sig, got, c.want)
		}
	}
}

func TestConclusiveAutomationReason(t *testing.T) {
	if got := conclusiveAutomationReason(map[string]interface{}{"webdriver": true}); got != "pulse_webdriver" {
		t.Errorf("webdriver reason = %q, want pulse_webdriver", got)
	}
	if got := conclusiveAutomationReason(map[string]interface{}{"automationArtifact": true}); got != "pulse_automation_artifact" {
		t.Errorf("artifact reason = %q, want pulse_automation_artifact", got)
	}
}
