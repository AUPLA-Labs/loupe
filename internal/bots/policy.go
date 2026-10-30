package bots

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Policy is the site's choice for every category and bot, plus custom bots.
// It's stored as YAML in bots.policy_file and edited from the dashboard.
type Policy struct {
	Categories map[string]Action `yaml:"categories,omitempty" json:"categories"`
	Bots       map[string]Action `yaml:"bots,omitempty" json:"bots"`
	// Spoofed is what happens when a request claims to be a verifiable bot
	// but fails verification: standard (default) or block.
	Spoofed Action `yaml:"spoofed,omitempty" json:"spoofed"`
	// Unverifiable is what happens to bots whose operator publishes no way to
	// verify them (no IP list, network or reverse DNS): block (default) or
	// standard. A per-bot "standard" override exempts a single bot.
	Unverifiable Action       `yaml:"unverifiable,omitempty" json:"unverifiable"`
	Robots       RobotsPolicy `yaml:"robots,omitempty" json:"robots"`
	Custom       []Bot        `yaml:"custom,omitempty" json:"custom"`
}

func (p *Policy) normalize() {
	if p.Categories == nil {
		p.Categories = map[string]Action{}
	}
	if p.Bots == nil {
		p.Bots = map[string]Action{}
	}
	if p.Spoofed == "" {
		p.Spoofed = Standard
	}
	if p.Unverifiable == "" {
		p.Unverifiable = Block
	}
	if p.Robots.Mode == "" {
		p.Robots.Mode = RobotsOff
	}
	if p.Custom == nil {
		p.Custom = []Bot{}
	}
	for i := range p.Custom {
		p.Custom[i].Custom = true
	}
}

var (
	idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,47}$`)
	// Tokens every browser sends; a custom bot keyed on one would match all traffic.
	genericTokens = map[string]bool{
		"mozilla": true, "applewebkit": true, "khtml": true, "gecko": true, "like": true,
		"chrome": true, "safari": true, "firefox": true, "edge": true, "mobile": true,
		"windows": true, "linux": true, "android": true, "iphone": true, "macintosh": true,
		"compatible": true, "version": true, "bot": true, "http": true, "https": true,
	}
)

// validate checks p against the catalog and returns a cleaned copy.
func (p Policy) validate(c *Catalog) (Policy, error) {
	p.normalize()
	if p.Spoofed != Standard && p.Spoofed != Block {
		return p, fmt.Errorf("spoofed must be standard or block, not %q", p.Spoofed)
	}
	if p.Unverifiable != Standard && p.Unverifiable != Block {
		return p, fmt.Errorf("unverifiable must be standard or block, not %q", p.Unverifiable)
	}
	if !p.Robots.valid() {
		return p, fmt.Errorf("robots mode must be off, merge or replace, not %q", p.Robots.Mode)
	}
	for id, a := range p.Categories {
		if c.category(id) == nil {
			return p, fmt.Errorf("unknown category %q", id)
		}
		if !a.valid() {
			return p, fmt.Errorf("category %s: unknown action %q", id, a)
		}
	}

	known := map[string]bool{}
	for _, b := range c.Bots {
		known[b.ID] = true
	}
	for i := range p.Custom {
		b := &p.Custom[i]
		if err := validateCustom(b, c, known); err != nil {
			return p, fmt.Errorf("custom bot %q: %w", b.Name, err)
		}
		known[b.ID] = true
	}
	for id, a := range p.Bots {
		if !known[id] {
			delete(p.Bots, id) // a removed custom bot's leftover override
			continue
		}
		if !a.valid() {
			return p, fmt.Errorf("bot %s: unknown action %q", id, a)
		}
	}
	return p, nil
}

func validateCustom(b *Bot, c *Catalog, taken map[string]bool) error {
	b.Name = strings.TrimSpace(b.Name)
	b.ID = strings.TrimSpace(b.ID)
	b.Custom = true
	switch {
	case b.Name == "":
		return errors.New("name is required")
	case !idRE.MatchString(b.ID):
		return errors.New("id must be 2–48 lowercase letters, digits or dashes")
	case taken[b.ID]:
		return fmt.Errorf("id %q is already used", b.ID)
	case c.category(b.Category) == nil:
		return fmt.Errorf("unknown category %q", b.Category)
	}
	var ua []string
	for _, t := range b.UA {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len(t) < 4 || genericTokens[strings.ToLower(strings.Trim(t, "/ "))] {
			return fmt.Errorf("user-agent token %q is too generic — it would match ordinary browsers", t)
		}
		ua = append(ua, t)
	}
	if len(ua) == 0 {
		return errors.New("at least one user-agent token is required")
	}
	b.UA = ua
	for _, r := range b.Ranges {
		if c.Sources[r] == nil && !strings.HasPrefix(r, "https://") {
			return fmt.Errorf("IP list %q must be an https:// URL", r)
		}
	}
	for _, s := range b.CIDRs {
		n := parseNet(strings.TrimSpace(s))
		if n == nil {
			return fmt.Errorf("%q is not an IP address or CIDR", s)
		}
		if ones, bits := n.Mask.Size(); (bits == 32 && ones < minPrefixV4) || (bits == 128 && ones < minPrefixV6) {
			return fmt.Errorf("%s is too wide (at most /%d IPv4, /%d IPv6)", n, minPrefixV4, minPrefixV6)
		}
	}
	for i, s := range b.PTR {
		s = strings.ToLower(strings.TrimSpace(s))
		if !strings.HasPrefix(s, ".") {
			s = "." + s
		}
		// ".com" would accept any host anyone controls under that TLD.
		if strings.Count(s, ".") < 2 || net.ParseIP(strings.TrimPrefix(s, ".")) != nil {
			return fmt.Errorf("reverse DNS suffix %q must be a domain like .example.com", b.PTR[i])
		}
		b.PTR[i] = s
	}
	for _, a := range b.ASN {
		if a == 0 {
			return errors.New("ASN 0 is not valid")
		}
	}
	return nil
}

// ParsePolicy decodes a policy file's bytes and fills in its defaults. It
// does not validate against the catalog.
func ParsePolicy(data []byte) (Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return p, err
	}
	p.normalize()
	return p, nil
}

func loadPolicy(path string) (Policy, time.Time, error) {
	p, _, mtime, err := loadPolicyBytes(path)
	return p, mtime, err
}

// loadPolicyBytes is loadPolicy that also returns the bytes it parsed, for
// recording exactly what was applied.
func loadPolicyBytes(path string) (Policy, []byte, time.Time, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Policy{}, nil, time.Time{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, nil, time.Time{}, err
	}
	p, err := ParsePolicy(data)
	if err != nil {
		return p, nil, time.Time{}, err
	}
	return p, data, fi.ModTime(), nil
}

const policyHeader = `# Loupe bot policy — managed from the dashboard (Bots page).
# Hand edits are picked up within a few seconds. See internal/bots/catalog.yaml
# for every built-in bot, category and IP list.
#
#   categories: per-category action (allow | standard | block); unset = built-in default
#   bots:       per-bot overrides of its category's action
#   spoofed:    a request claiming a verifiable bot that fails verification —
#               standard (normal protection) or block
#   unverifiable: bots with no IP list, network or reverse DNS to check —
#               block (default) or standard; a per-bot "standard" exempts one
#   robots:     mode off | merge (prepend to the site's robots.txt) | replace;
#               content_signals adds a contentsignals.org line
#   custom:     your own bots, same fields as the built-in catalog
`

// renderPolicy is the file's exact contents for p.
func renderPolicy(p Policy) ([]byte, error) {
	// Stable output: sorted maps make diffs and version comparisons readable.
	out := struct {
		Categories   *yaml.Node    `yaml:"categories,omitempty"`
		Bots         *yaml.Node    `yaml:"bots,omitempty"`
		Spoofed      Action        `yaml:"spoofed"`
		Unverifiable Action        `yaml:"unverifiable"`
		Robots       *RobotsPolicy `yaml:"robots,omitempty"`
		Custom       []Bot         `yaml:"custom,omitempty"`
	}{Categories: sortedMap(p.Categories), Bots: sortedMap(p.Bots), Spoofed: p.Spoofed, Unverifiable: p.Unverifiable, Custom: p.Custom}
	if p.Robots.Mode != RobotsOff && p.Robots.Mode != "" || p.Robots.ContentSignals {
		out.Robots = &p.Robots
	}
	var buf bytes.Buffer
	buf.WriteString(policyHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func savePolicy(path string, p Policy) error {
	data, err := renderPolicy(p)
	if err != nil {
		return err
	}
	return writePolicy(path, data)
}

func writePolicy(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// 0600 like every file the dashboard writes. Chmod covers a stale temp
	// file left with another mode, which WriteFile would keep.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func sortedMap(m map[string]Action) *yaml.Node {
	if len(m) == 0 {
		return nil
	}
	n := &yaml.Node{Kind: yaml.MappingNode}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		n.Content = append(n.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Value: string(m[k])})
	}
	return n
}
