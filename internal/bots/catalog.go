// Package bots identifies well-known crawlers and services, verifies that a
// request claiming to be one really comes from its operator, and applies the
// site's per-category / per-bot policy — modelled on Cloudflare's verified
// bots and AI Crawl Control.
//
// The bot directory (catalog.yaml) is compiled in. The site's choices —
// policy per category, overrides per bot, what to do with spoofed claims and
// any custom bots — live in a small YAML policy file the admin dashboard
// edits; changes apply within seconds, without a restart.
//
// Verification never trusts the User-Agent alone. A bot only counts as
// verified when its IP is in one of the operator's published IP lists
// (fetched and cached here), its network (ASN) is the operator's own, or its
// reverse DNS lands on the operator's domain and resolves back. Every failure
// mode is "treat as an ordinary visitor", never "let it through".
package bots

import (
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Action is what happens to a request from a bot.
type Action string

const (
	Allow    Action = "allow"    // verified bots skip all challenges
	Standard Action = "standard" // no special treatment: the normal protection pipeline decides
	Block    Action = "block"    // refused outright (by User-Agent claim alone — spoofing to get blocked isn't a bypass)
)

func (a Action) valid() bool { return a == Allow || a == Standard || a == Block }

type Category struct {
	ID      string `yaml:"id" json:"id"`
	Name    string `yaml:"name" json:"name"`
	About   string `yaml:"about" json:"about"`
	Default Action `yaml:"default" json:"default"`
	// Robots lists extra robots.txt tokens disallowed while the category is
	// blocked — opt-out tokens that aren't a crawler of their own.
	Robots []string `yaml:"robots,omitempty" json:"robots,omitempty"`
}

// Source is a published IP list. Loupe fetches it, extracts every IP and
// CIDR it contains (JSON or plain text, any layout), and caches the result.
type Source struct {
	ID       string `yaml:"-" json:"id"`
	Operator string `yaml:"operator" json:"operator"`
	URL      string `yaml:"url" json:"url"`
}

// Bot is one directory entry, built in or custom.
type Bot struct {
	ID       string   `yaml:"id" json:"id"`
	Name     string   `yaml:"name" json:"name"`
	Operator string   `yaml:"operator,omitempty" json:"operator,omitempty"`
	Category string   `yaml:"category" json:"category"`
	UA       []string `yaml:"ua" json:"ua"`
	Ranges   []string `yaml:"ranges,omitempty" json:"ranges,omitempty"` // source IDs, or https URLs for custom bots
	CIDRs    []string `yaml:"cidrs,omitempty" json:"cidrs,omitempty"`   // static ranges (custom bots)
	PTR      []string `yaml:"ptr,omitempty" json:"ptr,omitempty"`
	ASN      []uint   `yaml:"asn,omitempty" json:"asn,omitempty"`
	Robots   []string `yaml:"robots,omitempty" json:"robots,omitempty"` // robots.txt tokens; default: ua tokens cut at "/"
	NoRobots bool     `yaml:"norobots,omitempty" json:"norobots,omitempty"`
	Docs     string   `yaml:"docs,omitempty" json:"docs,omitempty"`
	About    string   `yaml:"about,omitempty" json:"about,omitempty"`
	Custom   bool     `yaml:"-" json:"custom"`
}

// Verifiable reports whether the bot has any way to prove a request is
// genuine. Unverifiable bots can be blocked or left to standard protection,
// never allowed.
func (b *Bot) Verifiable() bool {
	return len(b.Ranges) > 0 || len(b.CIDRs) > 0 || len(b.PTR) > 0 || len(b.ASN) > 0
}

type Catalog struct {
	Categories []Category         `yaml:"categories"`
	Sources    map[string]*Source `yaml:"sources"`
	Bots       []Bot              `yaml:"bots"`
}

//go:embed catalog.yaml
var catalogYAML []byte

func loadCatalog() (*Catalog, error) {
	var c Catalog
	if err := yaml.Unmarshal(catalogYAML, &c); err != nil {
		return nil, fmt.Errorf("bots catalog: %w", err)
	}
	for id, s := range c.Sources {
		s.ID = id
	}
	cats := map[string]bool{}
	for _, cat := range c.Categories {
		if !cat.Default.valid() {
			return nil, fmt.Errorf("bots catalog: category %s: bad default %q", cat.ID, cat.Default)
		}
		cats[cat.ID] = true
	}
	ids := map[string]bool{}
	for _, b := range c.Bots {
		switch {
		case ids[b.ID]:
			return nil, fmt.Errorf("bots catalog: duplicate bot %q", b.ID)
		case !cats[b.Category]:
			return nil, fmt.Errorf("bots catalog: bot %s: unknown category %q", b.ID, b.Category)
		case len(b.UA) == 0:
			return nil, fmt.Errorf("bots catalog: bot %s: no ua tokens", b.ID)
		}
		for _, r := range b.Ranges {
			if c.Sources[r] == nil {
				return nil, fmt.Errorf("bots catalog: bot %s: unknown source %q", b.ID, r)
			}
		}
		ids[b.ID] = true
	}
	return &c, nil
}

func (c *Catalog) category(id string) *Category {
	for i := range c.Categories {
		if c.Categories[i].ID == id {
			return &c.Categories[i]
		}
	}
	return nil
}

// sourceURL resolves a bot's ranges entry: a catalog source ID, or (custom
// bots) a URL given directly.
func (c *Catalog) sourceURL(ref string) string {
	if s := c.Sources[ref]; s != nil {
		return s.URL
	}
	if strings.HasPrefix(ref, "https://") {
		return ref
	}
	return ""
}
