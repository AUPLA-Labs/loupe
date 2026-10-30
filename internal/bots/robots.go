package bots

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// RobotsMode says whether, and how, Loupe manages /robots.txt.
type RobotsMode string

const (
	RobotsOff     RobotsMode = "off"     // the site's own robots.txt passes through untouched
	RobotsMerge   RobotsMode = "merge"   // Loupe's section, then the site's own file
	RobotsReplace RobotsMode = "replace" // Loupe's section only
)

// RobotsPolicy is the managed robots.txt setting, stored in the policy file.
type RobotsPolicy struct {
	Mode RobotsMode `yaml:"mode,omitempty" json:"mode"`
	// ContentSignals adds a Content-Signal line (contentsignals.org) stating
	// the site's search / ai-input / ai-train preferences, derived from the
	// category actions.
	ContentSignals bool `yaml:"content_signals,omitempty" json:"content_signals"`
}

func (r RobotsPolicy) valid() bool {
	switch r.Mode {
	case "", RobotsOff, RobotsMerge, RobotsReplace:
		return true
	}
	return false
}

const (
	robotsBegin = "# BEGIN Loupe managed section"
	robotsEnd   = "# END Loupe managed section"
)

var robotsTokenRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{2,}$`)

// robotsTokens returns b's robots.txt user-agent tokens.
func (b *Bot) robotsTokens() []string {
	if b.NoRobots {
		return nil
	}
	src := b.Robots
	if len(src) == 0 {
		for _, t := range b.UA {
			if i := strings.Index(t, "/"); i >= 0 {
				t = t[:i]
			}
			src = append(src, t)
		}
	}
	var out []string
	for _, t := range src {
		if t = strings.TrimSpace(t); robotsTokenRE.MatchString(t) {
			out = append(out, t)
		}
	}
	return out
}

// ContentSignals derives the contentsignals.org preferences from the
// category actions: a category set to block says "no", anything else "yes".
func (m *Manager) ContentSignals() map[string]bool {
	st := m.state.Load()
	cat := func(id string) Action {
		if a, ok := st.policy.Categories[id]; ok {
			return a
		}
		if c := m.catalog.category(id); c != nil {
			return c.Default
		}
		return Standard
	}
	return map[string]bool{
		"search":   cat("search") != Block,
		"ai-input": cat("ai_search") != Block || cat("ai_assistant") != Block,
		"ai-train": cat("ai_training") != Block,
	}
}

// RobotsSection renders Loupe's managed robots.txt block for the current
// policy: a Disallow group for every bot the site blocks, plus optional
// content signals. It is the same for every host.
func (m *Manager) RobotsSection() string {
	st := m.state.Load()
	seen := map[string]bool{}
	var tokens []string
	add := func(ts []string) {
		for _, t := range ts {
			if k := strings.ToLower(t); !seen[k] {
				seen[k] = true
				tokens = append(tokens, t)
			}
		}
	}
	for _, b := range st.bots {
		if a, _, _ := m.effectiveAction(st, b); a == Block {
			add(b.robotsTokens())
		}
	}
	for _, c := range m.catalog.Categories {
		a := c.Default
		if pa, ok := st.policy.Categories[c.ID]; ok {
			a = pa
		}
		if a == Block {
			add(c.Robots)
		}
	}
	sort.SliceStable(tokens, func(i, j int) bool { return strings.ToLower(tokens[i]) < strings.ToLower(tokens[j]) })

	var b strings.Builder
	b.WriteString(robotsBegin + "\n")
	b.WriteString("# Generated from this site's bot policy in Loupe. Edit the policy there;\n")
	b.WriteString("# changes made here are overwritten.\n")
	if st.policy.Robots.ContentSignals {
		sig := m.ContentSignals()
		yn := func(v bool) string {
			if v {
				return "yes"
			}
			return "no"
		}
		b.WriteString("#\n# Content signals (https://contentsignals.org) state how content from this\n")
		b.WriteString("# site may be used: search (building a search index and linking to results),\n")
		b.WriteString("# ai-input (answering AI queries in real time, e.g. grounding and RAG) and\n")
		b.WriteString("# ai-train (training or fine-tuning AI models).\n")
		fmt.Fprintf(&b, "User-agent: *\nContent-Signal: search=%s, ai-input=%s, ai-train=%s\n",
			yn(sig["search"]), yn(sig["ai-input"]), yn(sig["ai-train"]))
	}
	if len(tokens) > 0 {
		if st.policy.Robots.ContentSignals {
			b.WriteString("\n")
		}
		b.WriteString("# Bots this site blocks:\n")
		for _, t := range tokens {
			b.WriteString("User-agent: " + t + "\n")
		}
		b.WriteString("Disallow: /\n")
	}
	b.WriteString(robotsEnd + "\n")
	return b.String()
}

// RobotsMode reports the managed robots.txt mode in effect.
func (m *Manager) RobotsMode() RobotsMode {
	if mode := m.state.Load().policy.Robots.Mode; mode != "" {
		return mode
	}
	return RobotsOff
}

// MergeRobots puts Loupe's managed section in front of the site's own
// robots.txt (Cloudflare does the same). Crawlers combine every group that
// names them, so the site's own rules keep applying alongside. Any managed
// section already in the origin file (say, copied from a served response) is
// dropped so the two can't disagree.
func MergeRobots(section, origin string) string {
	origin = stripManaged(origin)
	origin = strings.TrimLeft(origin, "\r\n")
	if strings.TrimSpace(origin) == "" {
		return section
	}
	if !strings.HasSuffix(origin, "\n") {
		origin += "\n"
	}
	return section + "\n" + origin
}

func stripManaged(s string) string {
	for {
		i := strings.Index(s, robotsBegin)
		if i < 0 {
			return s
		}
		j := strings.Index(s[i:], robotsEnd)
		if j < 0 {
			return s[:i]
		}
		s = s[:i] + strings.TrimLeft(s[i+j+len(robotsEnd):], "\r\n")
	}
}

// ReplaceRobots is the full file in replace mode: the managed section, then
// an explicit allow-all for everyone else so the file is never ambiguous.
func ReplaceRobots(section string) string {
	return section + "\nUser-agent: *\nAllow: /\n"
}
