package bots

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func newTestManager(t *testing.T, p *Policy, asn func(net.IP) uint) *Manager {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bots.yaml")
	if p != nil {
		if err := savePolicy(path, *p); err != nil {
			t.Fatal(err)
		}
	}
	m, err := New(Options{PolicyFile: path, RangesDir: filepath.Join(dir, "ranges"), ASN: asn})
	if err != nil {
		t.Fatal(err)
	}
	m.lookupAddr = func(context.Context, string) ([]string, error) { return nil, errors.New("no dns in tests") }
	m.lookupHost = m.lookupAddr
	return m
}

func TestCatalogLoads(t *testing.T) {
	c, err := loadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Bots) < 60 || len(c.Categories) != 10 {
		t.Fatalf("catalog has %d bots, %d categories", len(c.Bots), len(c.Categories))
	}
	for _, b := range c.Bots {
		for _, tok := range b.UA {
			if len(tok) < 4 {
				t.Errorf("%s: token %q too short", b.ID, tok)
			}
		}
	}
}

func TestMatchRealUserAgents(t *testing.T) {
	m := newTestManager(t, nil, nil)
	st := m.state.Load()
	cases := map[string]string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)": "googlebot",
		"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)": "googlebot",
		"Mozilla/5.0 (compatible; Google-InspectionTool/1.0;)":                                                                        "google-inspectiontool",
		"AdsBot-Google (+http://www.google.com/adsbot.html)":                                                                          "google-ads",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)":                                                     "bingbot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)":                      "gptbot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot":                   "chatgpt-user",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot":            "oai-searchbot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)":                     "claudebot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)":                 "claude-user",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +https://www.anthropic.com)":            "claude-searchbot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)":     "perplexitybot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)": "perplexity-user",
		"meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)":                                   "meta-externalagent",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)":                                                   "facebookexternalhit",
		"Twitterbot/1.0":                "twitterbot",
		"TelegramBot (like TwitterBot)": "telegrambot",
		"LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)":                                                                                   "linkedinbot",
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)":                                                                                                      "ahrefsbot",
		"Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)":                                                                                             "semrushbot",
		"CCBot/2.0 (https://commoncrawl.org/faq/)":                                                                                                                                "ccbot",
		"Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)":                                                                                                     "bytespider",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0 ia_archiver":                                                                            "archive-org",
		"Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)":                                                                                                  "uptimerobot",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)": "applebot",
		"Mozilla/5.0 (compatible; DuckAssistBot/1.2; +http://duckduckgo.com/duckassistbot.html)":                                                                                  "duckassistbot",
		"DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)":                                                                                                              "duckduckbot",
	}
	for ua, want := range cases {
		b := st.match(ua)
		if b == nil || b.ID != want {
			got := "<nil>"
			if b != nil {
				got = b.ID
			}
			t.Errorf("match(%q) = %s, want %s", ua, got, want)
		}
	}

	// Ordinary browsers, including in-app browsers of the services above,
	// must never be mistaken for a bot.
	browsers := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/480.0.0.0]",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 350.0.0",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36 [Pinterest/Android]",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36 LinkedInApp",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 YaBrowser/25.8 Safari/537.36",
	}
	for _, ua := range browsers {
		if b := st.match(ua); b != nil {
			t.Errorf("browser UA %q matched bot %s", ua, b.ID)
		}
	}
}

func TestParseRanges(t *testing.T) {
	google := `{"creationTime":"x","prefixes":[{"ipv4Prefix":"66.249.64.0/27"},{"ipv6Prefix":"2001:4860:4801:10::/64"}]}`
	nets, err := parseRanges([]byte(google))
	if err != nil || len(nets) != 2 {
		t.Fatalf("google json: %v %v", nets, err)
	}
	ahrefs := `{"ips":[{"ip_address":"5.39.1.224"},{"ip_address":"5.39.1.225"}]}`
	if nets, err = parseRanges([]byte(ahrefs)); err != nil || len(nets) != 2 || nets[0].String() != "5.39.1.224/32" {
		t.Fatalf("ahrefs json: %v %v", nets, err)
	}
	html := `<html><td>3.224.62.45</td><td>2600:1f18::1</td><p>v1.2 at 12:30</p><td>10.0.0.1</td></html>`
	if nets, err = parseRanges([]byte(html)); err != nil || len(nets) != 2 {
		t.Fatalf("html: %v %v (private 10/8 must be dropped, 12:30 ignored)", nets, err)
	}
	if _, err = parseRanges([]byte("1.0.0.0/8\n")); err == nil {
		t.Fatal("a /8 must be rejected")
	}
	if _, err = parseRanges([]byte("nothing here")); err == nil {
		t.Fatal("an empty list must be an error")
	}
}

func TestClassify(t *testing.T) {
	p := &Policy{
		Categories: map[string]Action{"seo": Standard},
		Bots:       map[string]Action{"gptbot": Allow},
		Custom:     []Bot{{ID: "acme-monitor", Name: "Acme", Category: "monitoring", UA: []string{"AcmeMonitor"}, CIDRs: []string{"198.51.100.0/24"}}},
	}
	m := newTestManager(t, p, func(ip net.IP) uint {
		if ip.Equal(net.ParseIP("157.240.1.1")) {
			return 32934
		}
		return 64500
	})
	ip := net.ParseIP

	d := m.Classify(ip("198.51.100.7"), "AcmeMonitor/1.0")
	if d.Bot == nil || !d.Verified || d.Action != Allow || d.Status() != "verified" {
		t.Fatalf("custom verified: %+v", d)
	}
	d = m.Classify(ip("203.0.113.9"), "AcmeMonitor/1.0")
	if !d.Spoofed || d.Action != Standard || d.Status() != "spoofed" {
		t.Fatalf("custom spoofed: %+v", d)
	}
	d = m.Classify(ip("157.240.1.1"), "facebookexternalhit/1.1")
	if !d.Verified || d.Method != "network" || d.Action != Allow {
		t.Fatalf("asn verified: %+v", d)
	}
	d = m.Classify(ip("203.0.113.9"), "Mozilla/5.0 (compatible; Bytespider)")
	if d.Action != Block || d.Status() != "unverifiable" {
		t.Fatalf("training default block: %+v", d)
	}
	// Unverifiable bots are blocked by default — a User-Agent anyone can send.
	d = m.Classify(ip("203.0.113.9"), "Discordbot/2.0")
	if d.Action != Block || !d.Unverifiable || d.Status() != "unverifiable" {
		t.Fatalf("unverifiable bot should be blocked by default: %+v", d)
	}
	// GPTBot override allow, but no list loaded → can't verify → standard.
	d = m.Classify(ip("203.0.113.9"), "GPTBot/1.2")
	if !d.Overridden || d.Action != Standard || !d.Spoofed {
		t.Fatalf("gptbot without list: %+v", d)
	}
	if d := m.Classify(ip("1.2.3.4"), "Mozilla/5.0 Chrome/141"); d.Bot != nil {
		t.Fatalf("browser classified as %s", d.Bot.ID)
	}

	// A per-bot "standard" exempts one unverifiable bot…
	pol := m.Policy()
	pol.Bots["discordbot"] = Standard
	if _, err := m.Save(pol); err != nil {
		t.Fatal(err)
	}
	if d := m.Classify(ip("203.0.113.9"), "Discordbot/2.0"); d.Action != Standard || d.Unverifiable {
		t.Fatalf("exempted unverifiable bot: %+v", d)
	}
	// …and unverifiable: standard restores the old behaviour for all of them.
	delete(pol.Bots, "discordbot")
	pol.Unverifiable = Standard
	if _, err := m.Save(pol); err != nil {
		t.Fatal(err)
	}
	if d := m.Classify(ip("203.0.113.9"), "Slackbot-LinkExpanding 1.0"); d.Action != Standard {
		t.Fatalf("unverifiable: standard: %+v", d)
	}

	pol = m.Policy()
	pol.Spoofed = Block
	if _, err := m.Save(pol); err != nil {
		t.Fatal(err)
	}
	if d := m.Classify(ip("203.0.113.9"), "AcmeMonitor/1.0"); d.Action != Block {
		t.Fatalf("spoofed=block: %+v", d)
	}
}

func TestVerifyPTR(t *testing.T) {
	m := newTestManager(t, nil, nil)
	m.lookupAddr = func(_ context.Context, ip string) ([]string, error) {
		switch ip {
		case "66.249.66.1":
			return []string{"crawl-66-249-66-1.googlebot.com."}, nil
		case "6.6.6.6":
			return []string{"crawl-66-249-66-1.googlebot.com."}, nil // forged PTR
		}
		return nil, errors.New("nxdomain")
	}
	m.lookupHost = func(_ context.Context, host string) ([]string, error) {
		return []string{"66.249.66.1"}, nil
	}
	if c := m.verifyPTR(context.Background(), "66.249.66.1", []string{".googlebot.com"}); !c.OK {
		t.Fatalf("genuine: %+v", c)
	}
	if c := m.verifyPTR(context.Background(), "6.6.6.6", []string{".googlebot.com"}); c.OK {
		t.Fatalf("forged PTR passed: %+v", c)
	}
}

func TestValidateCustom(t *testing.T) {
	c, _ := loadCatalog()
	bad := []Bot{
		{ID: "x1", Name: "x", Category: "search", UA: []string{"Mozilla"}},
		{ID: "x2", Name: "x", Category: "search", UA: []string{"MyBot"}, CIDRs: []string{"10.0.0.0/8"}},
		{ID: "x3", Name: "x", Category: "search", UA: []string{"MyBot"}, PTR: []string{".com"}},
		{ID: "googlebot", Name: "x", Category: "search", UA: []string{"MyBot"}},
		{ID: "x5", Name: "x", Category: "nope", UA: []string{"MyBot"}},
		{ID: "x6", Name: "x", Category: "search", UA: []string{"MyBot"}, Ranges: []string{"http://insecure.example/ips"}},
	}
	for _, b := range bad {
		if _, err := (Policy{Custom: []Bot{b}}).validate(c); err == nil {
			t.Errorf("custom %+v accepted", b)
		}
	}
	good := Bot{ID: "mine", Name: "Mine", Category: "monitoring", UA: []string{"MineBot"}, PTR: []string{"example.com"}}
	p, err := (Policy{Custom: []Bot{good}}).validate(c)
	if err != nil || p.Custom[0].PTR[0] != ".example.com" {
		t.Fatalf("good custom: %v %+v", err, p.Custom)
	}
}

func TestMigrateKeepsLegacyBehaviour(t *testing.T) {
	m := newTestManager(t, nil, nil)
	p := m.migrate(&Legacy{
		Allow: []LegacyBot{
			{Name: "Googlebot", UAContains: "Googlebot", ValidPTR: []string{".googlebot.com"}},
			{Name: "Amazonbot", UAContains: "Amazonbot", ValidPTR: []string{".crawl.amazon.com"}},
			{Name: "GPTBot", UAContains: "GPTBot"},
			{Name: "Weird", UAContains: "WeirdCrawler", ValidPTR: []string{".weird.example"}},
			{Name: "Yahoo Slurp", UAContains: "Slurp", ValidPTR: []string{".crawl.yahoo.net"}},
			{Name: "googlebot", UAContains: "SomethingElse", ValidPTR: []string{".x.example"}},
		},
		Block: []string{"Bytespider", "EvilScraper"},
	})
	if p.Bots["googlebot"] != "" {
		t.Error("googlebot needs no override; search already allows")
	}
	if p.Bots["amazonbot"] != Allow || p.Bots["gptbot"] != Allow {
		t.Errorf("training bots that were allowed must stay allowed: %v", p.Bots)
	}
	if p.Bots["bytespider"] != "" {
		t.Error("bytespider: training already blocks")
	}
	if p.Categories["seo"] != Block {
		t.Error("seo was blocked by the old built-in list")
	}
	ids := map[string]Action{}
	for _, b := range p.Custom {
		ids[b.ID] = p.Bots[b.ID]
	}
	if ids["weird"] != Allow || ids["evilscraper"] != Block {
		t.Errorf("unknown legacy bots should become custom bots: %v", ids)
	}
	if _, ok := ids["yahoo-slurp"]; ok || len(p.Custom) != 2 {
		t.Errorf("short legacy token Slurp should map to the catalog's Yahoo Slurp, and a name clash to the catalog bot: %+v", p.Custom)
	}
}

func TestPolicyRoundTripAndHotReload(t *testing.T) {
	m := newTestManager(t, &Policy{Categories: map[string]Action{"preview": Block}}, nil)
	if m.Policy().Categories["preview"] != Block {
		t.Fatal("policy not loaded")
	}
	// Hand edit, then the watcher picks it up.
	path := m.opts.PolicyFile
	data, _ := os.ReadFile(path)
	edited := strings.Replace(string(data), "preview: block", "preview: standard", 1)
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	os.Chtimes(path, future, future)
	m.reloadIfChanged()
	if got := m.Policy().Categories["preview"]; got != Standard {
		t.Fatalf("after hand edit: %q", got)
	}
	// A broken edit keeps the last good policy and reports the error.
	os.WriteFile(path, []byte("categories: {preview: maybe}\n"), 0o644)
	future = future.Add(2 * time.Second)
	os.Chtimes(path, future, future)
	m.reloadIfChanged()
	if m.Policy().Categories["preview"] != Standard || m.Directory().PolicyErr == "" {
		t.Fatal("bad edit should be rejected with an error and the old policy kept")
	}
}

func TestRangeCacheSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s := newRangeStore(dir, time.Hour)
	nets, _ := parseRanges([]byte("192.0.2.0/24\n"))
	if err := s.writeCache("https://example.test/ips", nets); err != nil {
		t.Fatal(err)
	}
	s2 := newRangeStore(dir, time.Hour)
	s2.loadCached("https://example.test/ips")
	if !containsIP(s2.nets("https://example.test/ips"), net.ParseIP("192.0.2.9")) {
		t.Fatal("cached list not reloaded")
	}
	if s2.due("https://example.test/ips") {
		t.Fatal("a fresh cache file shouldn't be due")
	}
}

func TestParsePolicyMatchesLoad(t *testing.T) {
	m := newTestManager(t, &Policy{
		Categories: map[string]Action{"preview": Block},
		Custom:     []Bot{{ID: "acme-monitor", Name: "Acme Monitor", Category: "preview", UA: []string{"AcmeMonitor"}}},
	}, nil)
	data, err := os.ReadFile(m.PolicyFile())
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePolicy(data)
	if err != nil {
		t.Fatal(err)
	}
	want, _, err := loadPolicy(m.PolicyFile())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParsePolicy = %+v, loadPolicy = %+v; want equal", got, want)
	}
	if got.Spoofed == "" || got.Robots.Mode == "" || !got.Custom[0].Custom {
		t.Fatalf("ParsePolicy did not normalize: %+v", got)
	}
	if _, err := ParsePolicy([]byte("categories: [")); err == nil {
		t.Fatal("ParsePolicy accepted malformed YAML")
	}
}

func TestSavedPolicyIsPrivate(t *testing.T) {
	m := newTestManager(t, nil, nil)
	pol := m.Policy()
	pol.Categories["preview"] = Block
	if _, err := m.Save(pol); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(m.PolicyFile()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("policy file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}
}

func TestOnPolicyWrittenOnSave(t *testing.T) {
	m := newTestManager(t, nil, nil)
	var calls [][]byte
	m.SetOnPolicyWritten(func(b []byte) { calls = append(calls, b) })

	pol := m.Policy()
	pol.Categories["preview"] = Block
	if _, err := m.Save(pol); err != nil {
		t.Fatal(err)
	}
	onDisk, _ := os.ReadFile(m.PolicyFile())
	if len(calls) != 1 || string(calls[0]) != string(onDisk) {
		t.Fatalf("hook calls = %q, want one call with the bytes Save wrote:\n%s", calls, onDisk)
	}

	pol.Categories["preview"] = "maybe"
	if _, err := m.Save(pol); err == nil {
		t.Fatal("invalid policy saved")
	}
	if len(calls) != 1 {
		t.Fatalf("hook ran for a rejected save: %d calls", len(calls))
	}
}

func TestBotsHandEditRecorded(t *testing.T) {
	m := newTestManager(t, &Policy{Categories: map[string]Action{"preview": Block}}, nil)
	var calls [][]byte
	m.SetOnPolicyWritten(func(b []byte) { calls = append(calls, b) })

	path := m.PolicyFile()
	future := time.Now()
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		future = future.Add(2 * time.Second)
		os.Chtimes(path, future, future)
		m.reloadIfChanged()
	}

	write("categories: {preview: standard}\n")
	if len(calls) != 1 || string(calls[0]) != "categories: {preview: standard}\n" {
		t.Fatalf("after a good hand edit hook calls = %q, want the new file bytes", calls)
	}
	for _, bad := range []string{"categories: [", "categories: {preview: maybe}\n"} {
		write(bad)
		if len(calls) != 1 {
			t.Fatalf("hook ran for an unusable hand edit %q: %d calls", bad, len(calls))
		}
	}
}
