package bots

import (
	"strings"
	"testing"
)

func TestRobotsSection(t *testing.T) {
	m := newTestManager(t, &Policy{
		Bots:   map[string]Action{"gptbot": Allow, "yahoo-slurp": Block, "uptimerobot": Block},
		Robots: RobotsPolicy{Mode: RobotsMerge, ContentSignals: true},
	}, nil)
	s := m.RobotsSection()
	for _, want := range []string{
		"User-agent: ClaudeBot\n", "User-agent: CCBot\n", "User-agent: Bytespider\n", // ai_training blocked by default
		"User-agent: Google-Extended\n", "User-agent: Applebot-Extended\n", // the category's opt-out tokens
		"User-agent: Slurp\n",      // explicit robots token, not "Yahoo! Slurp"
		"User-agent: Discordbot\n", // unverifiable bots are blocked by default
		"Content-Signal: search=yes, ai-input=yes, ai-train=no\n",
		"Disallow: /\n", robotsBegin, robotsEnd,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("section missing %q:\n%s", want, s)
		}
	}
	for _, not := range []string{"User-agent: GPTBot", "UptimeRobot", "Googlebot"} {
		if strings.Contains(s, not) {
			t.Errorf("section must not contain %q (allowed, or never reads robots.txt):\n%s", not, s)
		}
	}
}

func TestRobotsSectionWithNothingBlocked(t *testing.T) {
	m := newTestManager(t, &Policy{Categories: map[string]Action{"ai_training": Allow}, Unverifiable: Standard}, nil)
	s := m.RobotsSection()
	if strings.Contains(s, "Disallow") || strings.Contains(s, "Content-Signal") {
		t.Fatalf("nothing blocked and signals off should give an empty section:\n%s", s)
	}
}

func TestMergeRobots(t *testing.T) {
	section := robotsBegin + "\nUser-agent: GPTBot\nDisallow: /\n" + robotsEnd + "\n"
	origin := "User-agent: *\nDisallow: /admin\n"
	if got := MergeRobots(section, origin); got != section+"\n"+origin {
		t.Fatalf("merge:\n%s", got)
	}
	// A stale managed section copied into the origin file is dropped.
	stale := robotsBegin + "\nUser-agent: Old\nDisallow: /\n" + robotsEnd + "\n\n" + origin
	if got := MergeRobots(section, stale); strings.Contains(got, "Old") || strings.Count(got, robotsBegin) != 1 {
		t.Fatalf("stale section kept:\n%s", got)
	}
	if got := MergeRobots(section, "  \n"); got != section {
		t.Fatalf("empty origin:\n%s", got)
	}
}

func TestRobotsModeValidation(t *testing.T) {
	c, _ := loadCatalog()
	if _, err := (Policy{Robots: RobotsPolicy{Mode: "sometimes"}}).validate(c); err == nil {
		t.Fatal("bad robots mode accepted")
	}
}
