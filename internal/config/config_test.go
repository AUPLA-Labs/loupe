package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRateLimitDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Abuse.RateLimit.Rate != 1.0 {
		t.Errorf("default rate = %v, want 1.0", cfg.Abuse.RateLimit.Rate)
	}
	if cfg.Abuse.RateLimit.Burst != 15 {
		t.Errorf("default burst = %v, want 15", cfg.Abuse.RateLimit.Burst)
	}
}

func TestClearanceBudgetDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	b := cfg.Abuse.ClearanceBudget
	if b.DocRate != 0.5 || b.DocBurst != 300 || b.AllRate != 5 || b.AllBurst != 3000 {
		t.Errorf("default clearance budget = %+v, want doc 0.5/300 and all 5/3000", b)
	}
}

func TestRateLimitOverride(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
backend: http://127.0.0.1:8081
abuse:
  rate_limit:
    rate: 0.5
    burst: 40
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Abuse.RateLimit.Rate != 0.5 {
		t.Errorf("rate = %v, want 0.5", cfg.Abuse.RateLimit.Rate)
	}
	if cfg.Abuse.RateLimit.Burst != 40 {
		t.Errorf("burst = %v, want 40", cfg.Abuse.RateLimit.Burst)
	}
}

func TestHardeningDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Hardening.RequestScore.Tier2 != 2 {
		t.Errorf("default request_score.tier2 = %v, want 2", cfg.Hardening.RequestScore.Tier2)
	}
	if cfg.Hardening.RequestScore.Tier3 != 4 {
		t.Errorf("default request_score.tier3 = %v, want 4", cfg.Hardening.RequestScore.Tier3)
	}
	if cfg.Hardening.RequestScore.Tier4 != 9 {
		t.Errorf("default request_score.tier4 = %v, want 9", cfg.Hardening.RequestScore.Tier4)
	}
	if len(cfg.Hardening.ExploitPaths) != 0 {
		t.Errorf("default exploit_paths should be empty, got %v", cfg.Hardening.ExploitPaths)
	}
}

func TestHardeningOverride(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
backend: http://127.0.0.1:8081
hardening:
  exploit_paths: ["/.env", "/wp-admin/install.php"]
  request_score:
    tier2: 3
    tier3: 6
    tier4: 10
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Hardening.RequestScore.Tier2 != 3 || cfg.Hardening.RequestScore.Tier3 != 6 || cfg.Hardening.RequestScore.Tier4 != 10 {
		t.Errorf("thresholds = %+v, want {3 6 10}", cfg.Hardening.RequestScore)
	}
	if len(cfg.Hardening.ExploitPaths) != 2 || cfg.Hardening.ExploitPaths[0] != "/.env" {
		t.Errorf("exploit_paths = %v", cfg.Hardening.ExploitPaths)
	}
}

func TestAutomationArtifactsDefault(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(cfg.Hardening.AutomationArtifacts) == 0 {
		t.Fatal("expected a non-empty default automation_artifacts list")
	}
	found := false
	for _, a := range cfg.Hardening.AutomationArtifacts {
		if a == "window.cdc_adoQpoasnfa76pfcZLmcfl_Array" {
			found = true
		}
	}
	if !found {
		t.Errorf("default list missing the chromedriver marker, got %v", cfg.Hardening.AutomationArtifacts)
	}
}

func TestNativeFnNamesDefault(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(cfg.Hardening.NativeFnNames) == 0 {
		t.Fatal("expected a non-empty default native_fn_names list")
	}
}

func TestReputationDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Reputation.HalfLifeHours != 6 {
		t.Errorf("default half_life_hours = %v, want 6", cfg.Reputation.HalfLifeHours)
	}
	if cfg.Reputation.SnapshotIntervalSeconds != 300 {
		t.Errorf("default snapshot_interval_seconds = %v, want 300", cfg.Reputation.SnapshotIntervalSeconds)
	}
	if cfg.Reputation.Floors.Tier2 != 4 || cfg.Reputation.Floors.Tier3 != 12 || cfg.Reputation.Floors.Tier4 != 40 {
		t.Errorf("default floors = %+v, want {4 12 40}", cfg.Reputation.Floors)
	}
	if cfg.Reputation.NonDatacenterMultiplier != 4 {
		t.Errorf("default non_datacenter_multiplier = %v, want 4", cfg.Reputation.NonDatacenterMultiplier)
	}
	if cfg.Reputation.SnapshotPath != "data/reputation.json" {
		t.Errorf("default snapshot_path = %q, want data/reputation.json (see TestPersistenceDefaults)", cfg.Reputation.SnapshotPath)
	}
}

func TestReputationOverride(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
backend: http://127.0.0.1:8081
reputation:
  half_life_hours: 3
  snapshot_path: "/tmp/reputation.json"
  snapshot_interval_seconds: 60
  floors: { tier2: 5, tier3: 15, tier4: 50 }
  non_datacenter_multiplier: 8
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Reputation.HalfLifeHours != 3 {
		t.Errorf("half_life_hours = %v, want 3", cfg.Reputation.HalfLifeHours)
	}
	if cfg.Reputation.SnapshotPath != "/tmp/reputation.json" {
		t.Errorf("snapshot_path = %q", cfg.Reputation.SnapshotPath)
	}
	if cfg.Reputation.SnapshotIntervalSeconds != 60 {
		t.Errorf("snapshot_interval_seconds = %v, want 60", cfg.Reputation.SnapshotIntervalSeconds)
	}
	if cfg.Reputation.Floors.Tier2 != 5 || cfg.Reputation.Floors.Tier3 != 15 || cfg.Reputation.Floors.Tier4 != 50 {
		t.Errorf("floors = %+v", cfg.Reputation.Floors)
	}
	if cfg.Reputation.NonDatacenterMultiplier != 8 {
		t.Errorf("non_datacenter_multiplier = %v, want 8", cfg.Reputation.NonDatacenterMultiplier)
	}
}

func TestGoodBotsAdditionalCrawlersParse(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
backend: http://127.0.0.1:8081
good_bots:
  bots:
    - name: GoogleOther
      ua_contains: GoogleOther
      valid_ptr: [".google.com", ".googlebot.com"]
    - name: Google-InspectionTool
      ua_contains: Google-InspectionTool
      valid_ptr: [".google.com", ".googlebot.com"]
    - name: Storebot-Google
      ua_contains: Storebot-Google
      valid_ptr: [".google.com", ".googlebot.com"]
    - name: AdsBot-Google
      ua_contains: AdsBot-Google
      valid_ptr: [".google.com", ".googlebot.com"]
    - name: Amazonbot
      ua_contains: Amazonbot
      valid_ptr: [".crawl.amazon.com"]
    - name: Yahoo Slurp
      ua_contains: Slurp
      valid_ptr: [".crawl.yahoo.net"]
    - name: PetalBot
      ua_contains: PetalBot
      valid_ptr: [".petalsearch.com"]
    - name: SeznamBot
      ua_contains: SeznamBot
      valid_ptr: [".seznam.cz"]
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(cfg.GoodBots.Bots) != 8 {
		t.Fatalf("got %d bots, want 8: %+v", len(cfg.GoodBots.Bots), cfg.GoodBots.Bots)
	}
	byName := make(map[string]BotDef, len(cfg.GoodBots.Bots))
	for _, b := range cfg.GoodBots.Bots {
		byName[b.Name] = b
	}
	amazonbot, ok := byName["Amazonbot"]
	if !ok {
		t.Fatal("missing Amazonbot entry")
	}
	if amazonbot.UAContains != "Amazonbot" || len(amazonbot.ValidPTR) != 1 || amazonbot.ValidPTR[0] != ".crawl.amazon.com" {
		t.Errorf("Amazonbot = %+v", amazonbot)
	}
}

func TestAICrawlersAllowIsVerifiedDefinitions(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
backend: http://127.0.0.1:8081
ai_crawlers:
  allow:
    - name: GPTBot
      ua_contains: GPTBot
      verified_cidr: "data/openai_cidrs.txt"
  block: ["Bytespider"]
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(cfg.AICrawlers.Allow) != 1 {
		t.Fatalf("got %d allow entries, want 1", len(cfg.AICrawlers.Allow))
	}
	got := cfg.AICrawlers.Allow[0]
	if got.Name != "GPTBot" || got.UAContains != "GPTBot" || got.VerifiedCIDR != "data/openai_cidrs.txt" {
		t.Errorf("allow[0] = %+v", got)
	}
	if len(cfg.AICrawlers.Block) != 1 || cfg.AICrawlers.Block[0] != "Bytespider" {
		t.Errorf("block = %v", cfg.AICrawlers.Block)
	}
}

func TestLumenDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	l := cfg.Lumen
	if l.Work != 100000 || l.PulseWork != 20000 || l.MemoryMB != 8 || l.PulseMemoryMB != 2 ||
		l.MaxMemoryMB != 32 || l.MaxLevel != 4 || l.Enforce || l.MaxConcurrentChecks != 8 {
		t.Errorf("lumen defaults = %+v", l)
	}
}

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestSecretFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac_secret")
	if err := os.WriteFile(path, []byte(testSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{HMACSecretFile: path}
	if err := ResolveSecret(cfg, false); err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	if cfg.HMACSecret != testSecret {
		t.Errorf("HMACSecret = %q, want the file's contents with the trailing newline trimmed", cfg.HMACSecret)
	}
}

func TestLoadResolvesSecretFile(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "data", "hmac_secret")
	cfgPath := filepath.Join(dir, "config.yaml")
	yml := "listen: \":8080\"\nbackend: \"http://127.0.0.1:8081\"\nhmac_secret_file: " + secretPath + "\n"
	if err := os.WriteFile(cfgPath, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	info, err := os.Stat(secretPath)
	if err != nil {
		t.Fatalf("Load did not create the secret file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("secret file mode = %v, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimSpace(string(data)); cfg.HMACSecret != want || len(want) != 64 {
		t.Errorf("HMACSecret = %q, want the file's trimmed 64-char contents %q", cfg.HMACSecret, want)
	}
}

func TestSecretGeneratedWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "hmac_secret")
	cfg := &Config{HMACSecretFile: path}
	if err := ResolveSecret(cfg, true); err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	if len(cfg.HMACSecret) != 64 {
		t.Fatalf("generated secret is %d chars, want 64 hex chars", len(cfg.HMACSecret))
	}
	if _, err := hex.DecodeString(cfg.HMACSecret); err != nil {
		t.Errorf("generated secret %q is not hex: %v", cfg.HMACSecret, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("secret file was not written: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("secret file mode = %v, want 0600", info.Mode().Perm())
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if dir.Mode().Perm() != 0o700 {
		t.Errorf("created parent dir mode = %v, want 0700", dir.Mode().Perm())
	}

	again := &Config{HMACSecretFile: path}
	if err := ResolveSecret(again, true); err != nil {
		t.Fatalf("second ResolveSecret: %v", err)
	}
	if again.HMACSecret != cfg.HMACSecret {
		t.Error("second ResolveSecret returned a different secret; it must reuse the file, not regenerate")
	}
}

func TestSecretMissingNoCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac_secret")
	cfg := &Config{HMACSecretFile: path}
	err := ResolveSecret(cfg, false)
	if err == nil {
		t.Fatal("expected an error when the file is missing and create is false")
	}
	if !strings.Contains(err.Error(), "hmac_secret_file") {
		t.Errorf("error %q should mention hmac_secret_file", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("create=false must not write the file")
	}
}

func TestInlineSecretStillWorks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac_secret")
	cfg := &Config{HMACSecret: testSecret, HMACSecretFile: path}
	if err := ResolveSecret(cfg, true); err != nil {
		t.Fatalf("ResolveSecret: %v", err)
	}
	if cfg.HMACSecret != testSecret {
		t.Errorf("HMACSecret = %q, want the inline value unchanged", cfg.HMACSecret)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("an inline secret must not cause hmac_secret_file to be created")
	}
}

func TestShortSecretRejected(t *testing.T) {
	short := strings.Repeat("a", 31)
	tests := []struct {
		name   string
		inline string
		file   string // contents of hmac_secret_file; empty means no file
	}{
		{"inline", short, ""},
		{"file", "", short + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hmac_secret")
			if tt.file != "" {
				if err := os.WriteFile(path, []byte(tt.file), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg := &Config{HMACSecret: tt.inline, HMACSecretFile: path}
			if err := ResolveSecret(cfg, true); err == nil {
				t.Error("expected an error for a secret under 32 characters")
			}
		})
	}
}

func TestLoadBytesLeavesSecretAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac_secret")
	cfg, err := LoadBytes([]byte("hmac_secret_file: " + path + "\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.HMACSecret != "" {
		t.Errorf("LoadBytes resolved the secret (%q); it must stay side-effect free", cfg.HMACSecret)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("LoadBytes created the secret file; it must stay side-effect free")
	}
}

func TestRulesConfigDefault(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rules.File != "data/rules.yaml" {
		t.Errorf("Rules.File = %q, want data/rules.yaml", cfg.Rules.File)
	}
	cfg, err = LoadBytes([]byte("backend: http://127.0.0.1:8081\nrules:\n  file: /etc/loupe/rules.yaml\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rules.File != "/etc/loupe/rules.yaml" {
		t.Errorf("Rules.File = %q, want the configured path", cfg.Rules.File)
	}
}

func TestEventRetention(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.Retention != "events" || cfg.Admin.MaxAgeDays != 30 {
		t.Fatalf("defaults: retention %q, max_age_days %d", cfg.Admin.Retention, cfg.Admin.MaxAgeDays)
	}
	if cfg.Admin.MaxAge() != 0 {
		t.Fatalf("event retention has max age %v, want 0", cfg.Admin.MaxAge())
	}
	if cfg.Admin.PruneLog == nil || !*cfg.Admin.PruneLog {
		t.Fatal("prune_log should default to true")
	}
	cfg, err = LoadBytes([]byte("backend: http://127.0.0.1:8081\nadmin:\n  retention: age\n  max_age_days: 7\n  prune_log: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.MaxAge() != 7*24*time.Hour || *cfg.Admin.PruneLog {
		t.Fatalf("max age %v, prune_log %v; want 7 days, false", cfg.Admin.MaxAge(), *cfg.Admin.PruneLog)
	}
	for _, bad := range []string{"retention: forever", "retention: age\n  max_age_days: -1"} {
		if _, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\nadmin:\n  " + bad + "\n")); err == nil {
			t.Errorf("%q loaded", bad)
		}
	}
}

func TestProxyDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(cfg.Proxy.Trusted) != 1 || cfg.Proxy.Trusted[0] != "loopback" {
		t.Errorf("default trusted = %q, want [loopback]", cfg.Proxy.Trusted)
	}
	if cfg.Proxy.ClientIPHeader != "X-Forwarded-For" {
		t.Errorf("default header = %q, want X-Forwarded-For", cfg.Proxy.ClientIPHeader)
	}
	cfg, err = LoadBytes([]byte("backend: http://127.0.0.1:8081\nproxy:\n  trusted: []\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Proxy.Trusted == nil || len(cfg.Proxy.Trusted) != 0 {
		t.Errorf("explicit [] = %#v, want empty and not defaulted", cfg.Proxy.Trusted)
	}
}

func TestProxyValidation(t *testing.T) {
	cases := []struct {
		yaml, wantErr string // wantErr "" = valid
	}{
		{"proxy:\n  trusted: [loopback, private, cloudflare, 203.0.113.0/24, 198.51.100.7, \"2001:db8::/32\"]\n", ""},
		{"proxy:\n  trusted: [cloudfare]\n", "cloudfare"},
		{"proxy:\n  trusted: [203.0.113.1/24]\n", "host bits"},
		{"proxy:\n  client_ip_header: \"X Forwarded\"\n", "client_ip_header"},
		{"proxy:\n  client_ip_header: Connection\n", "client_ip_header"},
	}
	for _, tc := range cases {
		_, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n" + tc.yaml))
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%q: %v", tc.yaml, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%q: error %v, want one containing %q", tc.yaml, err, tc.wantErr)
		}
	}
}

func TestDataDirDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\ndata_dir: /srv/l\n"))
	if err != nil {
		t.Fatal(err)
	}
	for got, want := range map[string]string{
		cfg.HMACSecretFile:   "/srv/l/hmac_secret",
		cfg.ASN.DBPath:       "/srv/l/asn.aupldb",
		cfg.ASN.TokenFile:    "/srv/l/aupldb_token",
		cfg.ASN.OverlayDir:   "/srv/l/overlay",
		cfg.BadIPs.CacheFile: "/srv/l/badips.csv",
		cfg.Rules.File:       "/srv/l/rules.yaml",
		cfg.Admin.AuditPath:  "/srv/l/audit.jsonl",
		cfg.Admin.HistoryDir: "/srv/l/history",
		cfg.Bots.PolicyFile:  "/srv/l/bots.yaml",
		cfg.Bots.RangesDir:   "/srv/l/ranges",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestDataDirUnsetKeepsRelative(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "data" || cfg.HMACSecretFile != "data/hmac_secret" {
		t.Errorf("DataDir %q, HMACSecretFile %q; want data, data/hmac_secret", cfg.DataDir, cfg.HMACSecretFile)
	}
}

func TestExplicitPathBeatsDataDir(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\ndata_dir: /srv/l\nbad_ips: {cache_file: x.csv}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BadIPs.CacheFile != "x.csv" {
		t.Errorf("CacheFile = %q, want x.csv", cfg.BadIPs.CacheFile)
	}
}

func TestDatacenterListDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\ndata_dir: /srv/l\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ASN.DatacenterASNsURL != DefaultDatacenterASNsURL || cfg.ASN.DatacenterASNsFile != "/srv/l/datacenter_asns.txt" || cfg.ASN.DatacenterASNsRefreshHours != 168 {
		t.Errorf("got url %q file %q every %dh", cfg.ASN.DatacenterASNsURL, cfg.ASN.DatacenterASNsFile, cfg.ASN.DatacenterASNsRefreshHours)
	}
	// "off" with no file: no list at all, so nothing has to exist.
	cfg, err = LoadBytes([]byte("backend: http://127.0.0.1:8081\nasn: {datacenter_asns_url: \"off\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ASN.DatacenterASNsURL != "off" || cfg.ASN.DatacenterASNsFile != "" {
		t.Errorf("off: url %q file %q, want off and no file", cfg.ASN.DatacenterASNsURL, cfg.ASN.DatacenterASNsFile)
	}
}

func TestAuthFileDefault(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\ndata_dir: " + dir + "\nadmin: {listen: \"0.0.0.0:9090\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.AuthFile != dir+"/admin_auth.yaml" {
		t.Errorf("AuthFile = %q", cfg.Admin.AuthFile)
	}
	if !cfg.Admin.NeedsSetup || cfg.Admin.AuthError != "" {
		t.Errorf("missing users file: NeedsSetup %v, AuthError %q; want true and none", cfg.Admin.NeedsSetup, cfg.Admin.AuthError)
	}
	os.WriteFile(dir+"/admin_auth.yaml", []byte("users: [\n"), 0o600)
	cfg, err = LoadBytes([]byte("backend: http://127.0.0.1:8081\ndata_dir: " + dir + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.NeedsSetup || cfg.Admin.AuthError == "" {
		t.Errorf("broken users file: NeedsSetup %v, AuthError %q; want false and an error", cfg.Admin.NeedsSetup, cfg.Admin.AuthError)
	}
}

func TestAdminAllowValidation(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\n"))
	if err != nil || !slices.Equal(cfg.Admin.Allow, []string{"loopback", "private"}) {
		t.Errorf("default allow = %v (%v), want [loopback private]", cfg.Admin.Allow, err)
	}
	for _, bad := range []string{"[]", "[foo]", "[1.2.3.4/33]"} {
		if _, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\nadmin: {allow: " + bad + "}\n")); err == nil {
			t.Errorf("allow %s: no error", bad)
		}
	}
}

// Events and reputation survive a restart unless switched off.
func TestPersistenceDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte("backend: http://127.0.0.1:8081\ndata_dir: /srv/l\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.LogPath != "/srv/l/events.jsonl" || cfg.Reputation.SnapshotPath != "/srv/l/reputation.json" {
		t.Errorf("log %q, snapshot %q", cfg.Admin.LogPath, cfg.Reputation.SnapshotPath)
	}
	cfg, err = LoadBytes([]byte("backend: http://127.0.0.1:8081\nadmin: {log_path: \"off\"}\nreputation: {snapshot_path: \"off\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.LogPath != "" || cfg.Reputation.SnapshotPath != "" {
		t.Errorf("off: log %q, snapshot %q; want both in memory only", cfg.Admin.LogPath, cfg.Reputation.SnapshotPath)
	}
}
