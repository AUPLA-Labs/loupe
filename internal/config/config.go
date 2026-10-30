package config

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AUPLA-Labs/loupe/internal/clientip"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen     string `yaml:"listen"`
	Backend    string `yaml:"backend"`
	HMACSecret string `yaml:"hmac_secret"` // deprecated: use hmac_secret_file
	CookieName string `yaml:"cookie_name"`
	CookieTTL  int    `yaml:"cookie_ttl"` // seconds

	// HMACSecretFile holds the secret Loupe signs cookies and tokens with.
	// Load creates it (0600) on first start; see ResolveSecret.
	HMACSecretFile string `yaml:"hmac_secret_file"`

	// DataDir is where every file Loupe keeps goes unless its own setting
	// names another path. Default "data", relative to the working directory.
	DataDir string `yaml:"data_dir"`

	ASN   ASNConfig   `yaml:"asn"`
	Lumen LumenConfig `yaml:"lumen"`
	Admin AdminConfig `yaml:"admin"`

	Bots       BotsConfig       `yaml:"bots"`
	GoodBots   GoodBotsConfig   `yaml:"good_bots"`   // deprecated: migrated into bots.policy_file on first start
	AICrawlers AICrawlersConfig `yaml:"ai_crawlers"` // deprecated: migrated into bots.policy_file on first start
	BadBotUAs  BadBotUAsConfig  `yaml:"bad_bot_uas"`
	Abuse      AbuseConfig      `yaml:"abuse"`
	Hardening  HardeningConfig  `yaml:"hardening"`
	Reputation ReputationConfig `yaml:"reputation"`
	BadIPs     BadIPsConfig     `yaml:"bad_ips"`
	Rules      RulesConfig      `yaml:"rules"`
	Limits     LimitsConfig     `yaml:"limits"`
	Proxy      ProxyConfig      `yaml:"proxy"`
	Behaviour  BehaviourConfig  `yaml:"behaviour"`

	ChallengePath string `yaml:"challenge_path"`
	VerifyPath    string `yaml:"verify_path"`
}

// BotsConfig locates the verified-bot policy and IP-list cache. The bot
// directory itself is built in (internal/bots/catalog.yaml); the policy file
// holds the site's per-category and per-bot choices and is edited from the
// admin dashboard, applying without a restart.
type BotsConfig struct {
	PolicyFile   string `yaml:"policy_file"`   // default "<data_dir>/bots.yaml"
	RangesDir    string `yaml:"ranges_dir"`    // default "<data_dir>/ranges"
	RefreshHours int    `yaml:"refresh_hours"` // how often published IP lists are re-fetched; default 24
}

// AICrawlersConfig makes a deliberate, per-crawler choice about specific AI
// crawlers, rather than leaving them to fall through to the generic
// challenge flow. Allow entries are BotDef definitions verified the same
// way as good_bots (by published CIDR ranges, since most AI crawlers don't
// support PTR the way search engines do) — this is what stops a UA header
// alone from bypassing the whole pipeline. Block stays plain UA substrings:
// spoofing a UA to get blocked isn't a bypass, so it needs no verification.
type AICrawlersConfig struct {
	Allow []BotDef `yaml:"allow"`
	Block []string `yaml:"block"`
}

// BadBotUAsConfig extends the built-in bot/scanner User-Agent substring list
// (see defaultBotUAPatterns) without requiring a rebuild.
type BadBotUAsConfig struct {
	Patterns     []string `yaml:"patterns"`
	PatternsFile string   `yaml:"patterns_file"`
}

// AbuseConfig controls the repeat-offender cooldown: after FailThreshold
// consecutive challenge/verification failures from the same IP, it gets a
// hard block for CooldownSeconds instead of an endless stream of fresh,
// equally-easy challenges.
type AbuseConfig struct {
	FailThreshold   int             `yaml:"fail_threshold"`   // default 5
	CooldownSeconds int             `yaml:"cooldown_seconds"` // default 900 (15 min)
	RateLimit       RateLimitConfig `yaml:"rate_limit"`

	ClearanceBudget ClearanceBudgetConfig `yaml:"clearance_budget"`
}

// RateLimitConfig bounds how fast a single client key may make requests that
// are not already cleared. Cleared sessions are held to ClearanceBudget
// instead, so ordinary browsing with many subresources is unaffected; a
// genuine first-time visitor makes one or two uncleared navigations.
type RateLimitConfig struct {
	Rate  float64 `yaml:"rate"`  // tokens per second; default 1.0
	Burst float64 `yaml:"burst"` // bucket capacity; default 15
}

// ClearanceBudgetConfig bounds what one clearance cookie may spend, however
// many addresses it is replayed from: a bucket for documents (top-level
// navigations) and a larger one for every request including subresources.
type ClearanceBudgetConfig struct {
	DocRate  float64 `yaml:"doc_rate"`  // documents per second; default 0.5
	DocBurst float64 `yaml:"doc_burst"` // document bucket capacity; default 300
	AllRate  float64 `yaml:"all_rate"`  // requests per second; default 5
	AllBurst float64 `yaml:"all_burst"` // request bucket capacity; default 3000
}

// HardeningConfig groups the pre-JS request scoring thresholds and the
// operator-supplied lists (exploit paths, automation artifacts and
// native-function names) that let the
// hardening signals be retuned from config without a rebuild.
type HardeningConfig struct {
	ExploitPaths        []string           `yaml:"exploit_paths"` // substrings; empty by default (site-specific)
	RequestScore        RequestScoreConfig `yaml:"request_score"`
	AutomationArtifacts []string           `yaml:"automation_artifacts"`
	NativeFnNames       []string           `yaml:"native_fn_names"`
}

// defaultAutomationArtifacts are property paths no real browser ever
// defines — presence of any is conclusive proof of automation tooling, not
// evidence. Kept as data (overridable via config) rather than code, since
// new framework names appearing over time is expected and should not need
// a rebuild to respond to.
var defaultAutomationArtifacts = []string{
	"window.cdc_adoQpoasnfa76pfcZLmcfl_Array",
	"document.$cdc_asdjflasutopfhvcZLmcfl_",
	"window.__playwright_run",
	"window.__puppeteer_utility_world__",
	"window.__webdriver_evaluate",
	"window.__driver_evaluate",
	"window.__fxdriver_evaluate",
	"window.__selenium_unwrapped",
	"window._Selenium_IDE_Recorder",
	"window.domAutomation",
	"window.domAutomationController",
	"window._phantom",
	"window.callPhantom",
	"window.__nightmare",
}

// defaultNativeFnNames are native functions curated because they are
// commonly monkey-patched by anti-detect browsers and stealth plugins, while
// being safe to read without side effects. native_fn_tampered requires two
// or more of these to fail the "[native code]" check before it fires, so
// that a single API legitimately patched by an ad blocker or privacy
// extension does not trigger it alone.
var defaultNativeFnNames = []string{
	"Function.prototype.bind",
	"Object.getOwnPropertyDescriptor",
	"navigator.permissions.query",
	"Array.prototype.push",
	"Date.prototype.getTimezoneOffset",
}

// RequestScoreConfig maps a reflexRequestScore result onto the challenge
// tier ladder (internal/tier). A score below Tier2 leaves the request at its
// default tier (Pulse); each threshold raises it one step further.
type RequestScoreConfig struct {
	Tier2 int `yaml:"tier2"` // score >= this → Lumen auto (no interaction); default 2
	Tier3 int `yaml:"tier3"` // score >= this → SingleClick (manual challenge); default 4
	Tier4 int `yaml:"tier4"` // score >= this → Prism (drag puzzle); default 9
}

// ReputationConfig controls the decaying per-IP/per-ASN "pressure" store
// (internal/reputation) that raises the challenge tier floor for traffic
// sources with a history of automation. It is saved to SnapshotPath (in
// data_dir unless set) so a restart keeps it; "off" keeps it in memory only,
// like AdminConfig.LogPath.
type ReputationConfig struct {
	HalfLifeHours           float64          `yaml:"half_life_hours"`           // default 6
	SnapshotPath            string           `yaml:"snapshot_path"`             // default "<data_dir>/reputation.json"; "off" = memory only
	SnapshotIntervalSeconds int              `yaml:"snapshot_interval_seconds"` // default 300 (5 min)
	Floors                  ReputationFloors `yaml:"floors"`
	NonDatacenterMultiplier float64          `yaml:"non_datacenter_multiplier"` // default 4
}

// ReputationFloors are the pressure thresholds that raise the challenge tier.
// Applied unconditionally to per-IP pressure; applied to per-ASN pressure
// scaled by NonDatacenterMultiplier (and capped at SingleClick) unless the
// ASN is classified as datacenter/hosting.
type ReputationFloors struct {
	Tier2 float64 `yaml:"tier2"` // default 4  (Lumen auto)
	Tier3 float64 `yaml:"tier3"` // default 12 (SingleClick)
	Tier4 float64 `yaml:"tier4"` // default 40 (Prism)
}

// BadIPsConfig turns on the known-bad-IP feed (internal/badip): a daily
// list of addresses with how many public blacklists name each one. Listed
// on ChallengeAt or more lists gets the Prism puzzle, on BlockAt or more a
// 403; BlockAt 0 never blocks on the list alone.
type BadIPsConfig struct {
	Enabled      bool   `yaml:"enabled"`
	URL          string `yaml:"url"`           // default the auplalabs CSV feed
	CacheFile    string `yaml:"cache_file"`    // last good copy; default "data/badips.csv"
	RefreshHours int    `yaml:"refresh_hours"` // default 24
	ChallengeAt  int    `yaml:"challenge_at"`  // default 1
	BlockAt      int    `yaml:"block_at"`      // 0 = never block
}

// RulesConfig locates the operator's rule file (internal/rules). It is read
// at startup and re-read within seconds of a change; a missing file is an
// empty rule set.
type RulesConfig struct {
	File string `yaml:"file"` // default "<data_dir>/rules.yaml"
}

// BehaviourConfig controls post-clearance behaviour scoring. Signals are
// always recorded on the clearance event; Enforce also drops the clearance
// of a client whose navigation looks scripted.
type BehaviourConfig struct {
	Enforce bool `yaml:"enforce"` // default false: record only
}

// LimitsConfig bounds requests before any other check runs. Requests from
// loopback and private addresses are exempt.
// ProxyConfig says which front proxies Loupe believes about the visitor's
// address and scheme; see docs/proxy.md.
type ProxyConfig struct {
	// Trusted holds CIDRs, bare addresses or the presets loopback, private
	// and cloudflare. Unset means [loopback]; an explicit [] trusts nobody.
	Trusted []string `yaml:"trusted"`
	// ClientIPHeader is the header a trusted proxy puts the visitor's
	// address in. Default X-Forwarded-For.
	ClientIPHeader string `yaml:"client_ip_header"`
}

type LimitsConfig struct {
	MaxURLBytes    int      `yaml:"max_url_bytes"`    // whole request target, path and query; default 8192 (414 beyond)
	MaxQueryParams int      `yaml:"max_query_params"` // default 256 (400 beyond)
	MaxBodyBytes   int64    `yaml:"max_body_bytes"`   // 0 = no limit (413 beyond)
	AllowedMethods []string `yaml:"allowed_methods"`  // default GET HEAD POST PUT PATCH DELETE OPTIONS (405 otherwise)
	// UploadPaths are path prefixes that may carry bodies up to
	// UploadMaxBodyBytes instead (0 = no limit there).
	UploadPaths        []string `yaml:"upload_paths"`
	UploadMaxBodyBytes int64    `yaml:"upload_max_body_bytes"`
}

// DefaultAllowedMethods are the methods allowed when limits.allowed_methods
// is unset.
var DefaultAllowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

// validateLimits rejects limits that can't be enforced as written.
func validateLimits(l *LimitsConfig) error {
	if l.MaxBodyBytes < 0 || l.UploadMaxBodyBytes < 0 {
		return fmt.Errorf("limits: body sizes can't be negative (0 means no limit)")
	}
	for i, m := range l.AllowedMethods {
		up := strings.ToUpper(strings.TrimSpace(m))
		if up == "" || strings.IndexFunc(up, func(r rune) bool { return r < 'A' || r > 'Z' }) >= 0 {
			return fmt.Errorf("limits.allowed_methods: %q is not a method name", m)
		}
		l.AllowedMethods[i] = up
	}
	for _, p := range l.UploadPaths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("limits.upload_paths: %q must start with /", p)
		}
	}
	return nil
}

// DefaultBadIPsURL is the feed used when bad_ips.url is unset.
const DefaultBadIPsURL = "https://api.auplalabs.com/v1/badips.csv"

// DefaultAUPLAAPI is the AUPLA API used when asn.api_url is unset.
const DefaultAUPLAAPI = "https://api.auplalabs.com"

// DefaultDatacenterASNsURL is a community list of hosting, VPN and proxy
// networks (github.com/bountyyfi/bad-asn-list).
const DefaultDatacenterASNsURL = "https://raw.githubusercontent.com/bountyyfi/bad-asn-list/refs/heads/main/all.txt"

// ASNConfig points at the AUPLA database (internal/aupldb): Loupe keeps a
// local copy in DBPath and checks APIURL for a new build every
// RefreshMinutes. Per address it gives the network (ASN, name, type), the
// country and the registration. Downloads need the token in TokenFile,
// which Loupe gets and writes itself once the AUPLA terms are accepted in
// the dashboard. The overlay lists (Tor exits, VPN servers, cloud ranges,
// verified crawlers) are fetched from their publishers into OverlayDir and
// need no token.
type ASNConfig struct {
	DBPath         string `yaml:"db_path"`         // default "<data_dir>/asn.aupldb"
	APIURL         string `yaml:"api_url"`         // default DefaultAUPLAAPI
	TokenFile      string `yaml:"token_file"`      // default "<data_dir>/aupldb_token"
	RefreshMinutes int    `yaml:"refresh_minutes"` // default 10
	// PublicKeys are the base64 Ed25519 keys the database must be signed
	// by. Unset = AUPLA's own (aupldb.DefaultPublicKeys).
	PublicKeys         []string `yaml:"public_keys"`
	BlockedASNs        []uint   `yaml:"blocked_asns"`
	AllowedASNs        []uint   `yaml:"allowed_asns"`
	DatacenterASNs     []uint   `yaml:"datacenter_asns"`
	DatacenterASNsFile string   `yaml:"datacenter_asns_file"` // default "<data_dir>/datacenter_asns.txt" unless the URL is off
	// DatacenterASNsURL is a published list Loupe keeps DatacenterASNsFile
	// current from, every DatacenterASNsRefreshHours (default 168). Default
	// DefaultDatacenterASNsURL; "off" leaves the file to you.
	DatacenterASNsURL          string `yaml:"datacenter_asns_url"`
	DatacenterASNsRefreshHours int    `yaml:"datacenter_asns_refresh_hours"`
	// DatacenterCategories are the network types that count as datacenters
	// on top of the listed ASNs: isp, business, hosting, education_research,
	// government_admin. Unset = [hosting]; [] = listed ASNs only.
	DatacenterCategories []string `yaml:"datacenter_categories"`
	OverlayDir           string   `yaml:"overlay_dir"` // default "overlay" next to db_path; "off" disables the overlay
}

// LumenConfig sets the cost of Lumen, the proof-of-work + proof-of-space
// check (internal/lumen). Work and memory are the Standard level's; the
// other levels scale from them.
type LumenConfig struct {
	Work          int64 `yaml:"work"`            // challenge page SHA-256 search space; default 100000
	PulseWork     int64 `yaml:"pulse_work"`      // silent pulse check's; default 20000
	MemoryMB      int   `yaml:"memory_mb"`       // challenge page scrypt memory; default 8
	PulseMemoryMB int   `yaml:"pulse_memory_mb"` // pulse's; default 2
	MaxMemoryMB   int   `yaml:"max_memory_mb"`   // ceiling for every level; default 32
	MaxLevel      int   `yaml:"max_level"`       // highest level issued, 1–4 (Standard–Blinding); default 4
	// Enforce turns on level scaling and makes a wrong or missing
	// proof-of-space fail. Off (shadow mode), levels are computed and
	// logged, the old pressure-based difficulty is served, and space
	// failures are only logged.
	Enforce bool `yaml:"enforce"`
	// MaxConcurrentChecks bounds simultaneous proof-of-space checks; the
	// server's worst case is this × max_memory_mb. Default 8.
	MaxConcurrentChecks int `yaml:"max_concurrent_checks"`
}

// BotDef describes a single verified-crawler rule, verified by exactly one
// of two methods depending on which field is set:
//   - valid_ptr: reverse-then-forward DNS (search engines: Googlebot, Bingbot).
//   - verified_cidr: IP membership in a file of published ranges (AI crawlers,
//     which mostly don't support the PTR convention search engines use).
//
// ua_contains is matched case-insensitively against the User-Agent either way.
type BotDef struct {
	Name         string   `yaml:"name"`
	UAContains   string   `yaml:"ua_contains"`
	ValidPTR     []string `yaml:"valid_ptr,omitempty"`
	VerifiedCIDR string   `yaml:"verified_cidr,omitempty"`
}

type GoodBotsConfig struct {
	TTL  int      `yaml:"ttl"` // verification cache TTL in seconds; default 3600
	Bots []BotDef `yaml:"bots"`
}

type AdminConfig struct {
	Listen string `yaml:"listen"` // default "127.0.0.1:9090"
	// Allow is who may connect to the console, judged by the connecting
	// address (never a forwarded header): addresses, CIDRs or the presets of
	// proxy.trusted. Default [loopback, private].
	Allow    []string `yaml:"allow"`
	LogPath  string   `yaml:"log_path"`  // JSONL event log; default "<data_dir>/events.jsonl"; "off" = memory only
	Capacity int      `yaml:"capacity"`  // ring buffer size; default 5000
	AuthFile string   `yaml:"auth_file"` // path to the users file (accounts, roles, 2FA); default "<data_dir>/admin_auth.yaml". The first-run setup link or `loupe -setup-admin` creates it

	AuditPath   string `yaml:"audit_path"`   // JSONL record of admin actions; default "data/audit.jsonl"
	HistoryDir  string `yaml:"history_dir"`  // saved versions of config.yaml and bots.yaml; default "data/history"
	HistoryKeep int    `yaml:"history_keep"` // versions kept per file; default 50, at least 2

	// Retention is how the event history is limited: "events" (the default)
	// keeps the newest Capacity events, "age" deletes events older than
	// MaxAgeDays, for data-protection rules that cap how long logs are
	// kept. PruneLog (default true) applies the limit to LogPath as well;
	// false limits only the dashboard's memory and keeps the log whole.
	Retention  string `yaml:"retention"`
	MaxAgeDays int    `yaml:"max_age_days"` // with retention "age"; default 30
	PruneLog   *bool  `yaml:"prune_log"`

	// Users, loaded from AuthFile at startup. Empty with no AuthFile means
	// no authentication, which is only valid when Listen is loopback-only.
	Users []AdminUser `yaml:"-"`
	// AuthError says why AuthFile could not be loaded ("" when it loaded).
	// The config still loads, so a broken users file never stops the proxy;
	// the console stays locked until the file is fixed.
	AuthError string `yaml:"-"`
	// NeedsSetup is set when AuthFile doesn't exist yet: the console then
	// offers the first-run setup link instead of locking.
	NeedsSetup bool `yaml:"-"`
	Require2FA bool `yaml:"require_2fa"` // every user must have a second factor to sign in
}

const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// AdminUser is one dashboard account in the admin auth file.
type AdminUser struct {
	Username       string   `yaml:"username"`
	PasswordHash   string   `yaml:"password_hash"`
	Role           string   `yaml:"role"`
	TOTPSecret     string   `yaml:"totp_secret,omitempty"`    // base32, no padding
	TOTPLastStep   int64    `yaml:"totp_last_step,omitempty"` // last accepted 30s step
	RecoveryHashes []string `yaml:"recovery_hashes,omitempty"`
}

// AdminAuth is the credentials file referenced by AdminConfig.AuthFile.
// It's kept separate from the main config.yaml so the password hashes
// never end up alongside that file's hand-edited comments and formatting.
//
// The Username and PasswordHash fields are the old single-user layout. They
// are read so an existing file keeps working, folded into Users, and never
// written back.
type AdminAuth struct {
	Users        []AdminUser `yaml:"users"`
	Username     string      `yaml:"username,omitempty"`      // legacy
	PasswordHash string      `yaml:"password_hash,omitempty"` // legacy
}

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

const adminAuthHeader = "# Managed by Loupe (dashboard and loupe -setup-admin). Hand edits are picked up within a second.\n"

// ParseAdminAuth reads an admin auth file in either layout and validates it.
func ParseAdminAuth(data []byte) (*AdminAuth, error) {
	var a AdminAuth
	if err := yaml.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	haveUser, haveHash := a.Username != "", a.PasswordHash != ""
	switch {
	case haveUser != haveHash:
		return nil, errors.New("admin auth file must set both username and password_hash")
	case haveUser && len(a.Users) > 0:
		return nil, errors.New("admin auth file mixes the old username/password_hash keys with users:")
	case haveUser:
		a.Users = []AdminUser{{Username: a.Username, PasswordHash: a.PasswordHash, Role: RoleAdmin}}
		a.Username, a.PasswordHash = "", ""
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

func LoadAdminAuth(path string) (*AdminAuth, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseAdminAuth(data)
}

// Validate checks the users list. The file is hand-editable and holds the
// only way into the dashboard, so it is strict.
func (a *AdminAuth) Validate() error {
	if len(a.Users) == 0 {
		return errors.New("no users")
	}
	seen := make(map[string]bool, len(a.Users))
	admins := 0
	for _, u := range a.Users {
		if !usernameRE.MatchString(u.Username) {
			return fmt.Errorf("invalid username %q", u.Username)
		}
		key := strings.ToLower(u.Username)
		if seen[key] {
			return fmt.Errorf("duplicate username %q", u.Username)
		}
		seen[key] = true
		if !strings.HasPrefix(u.PasswordHash, "$2") {
			return fmt.Errorf("user %q has no valid password_hash", u.Username)
		}
		switch u.Role {
		case RoleAdmin:
			admins++
		case RoleViewer:
		default:
			return fmt.Errorf("user %q has unknown role %q", u.Username, u.Role)
		}
		if u.TOTPSecret != "" {
			raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(u.TOTPSecret))
			if err != nil || len(raw) < 16 {
				return fmt.Errorf("user %q has an invalid totp_secret", u.Username)
			}
		}
		for _, h := range u.RecoveryHashes {
			if !strings.HasPrefix(h, "$2") {
				return fmt.Errorf("user %q has an invalid recovery hash", u.Username)
			}
		}
	}
	if admins == 0 {
		return errors.New("at least one admin must remain")
	}
	return nil
}

// SaveAdminAuth validates a and writes it in the current layout, atomically
// with mode 0600. Nothing is written when validation fails.
func SaveAdminAuth(path string, a *AdminAuth) error {
	if err := a.Validate(); err != nil {
		return err
	}
	body, err := yaml.Marshal(struct {
		Users []AdminUser `yaml:"users"`
	}{a.Users})
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append([]byte(adminAuthHeader), body...))
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := LoadBytes(data)
	if err != nil {
		return nil, err
	}
	// Only Load touches the secret file: LoadBytes also serves the
	// dashboard's validate and settings paths, which must not write anything.
	if err := ResolveSecret(cfg, true); err != nil {
		return nil, err
	}
	return cfg, nil
}

// minSecretLen is the shortest HMAC secret ResolveSecret accepts.
const minSecretLen = 32

// ResolveSecret fills cfg.HMACSecret. An inline hmac_secret wins, so a config
// written before hmac_secret_file existed keeps working (and keeps its issued
// cookies). Otherwise the secret is read from hmac_secret_file; if that file
// is missing and create is set, a fresh random one is written first.
func ResolveSecret(cfg *Config, create bool) error {
	if cfg.HMACSecret != "" {
		log.Printf("config: hmac_secret in config.yaml is deprecated, move it to hmac_secret_file (%s)", cfg.HMACSecretFile)
		if len(cfg.HMACSecret) < minSecretLen {
			return fmt.Errorf("hmac_secret must be at least %d characters", minSecretLen)
		}
		return nil
	}

	data, err := os.ReadFile(cfg.HMACSecretFile)
	if errors.Is(err, os.ErrNotExist) && create {
		if err := generateSecretFile(cfg.HMACSecretFile); err != nil {
			return fmt.Errorf("hmac_secret_file: %w", err)
		}
		data, err = os.ReadFile(cfg.HMACSecretFile)
	}
	if err != nil {
		return fmt.Errorf("hmac_secret_file: %w", err)
	}
	secret := strings.TrimSpace(string(data))
	if len(secret) < minSecretLen {
		return fmt.Errorf("hmac_secret_file %s: secret must be at least %d characters", cfg.HMACSecretFile, minSecretLen)
	}
	cfg.HMACSecret = secret
	return nil
}

// generateSecretFile writes 32 random bytes, hex-encoded, to path readable by
// this user only.
func generateSecretFile(path string) error {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hmac_secret-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(hex.EncodeToString(buf) + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func LoadBytes(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	applyDefaults(&cfg)

	// A users file that is missing, unreadable or invalid is recorded, not
	// returned: failing here would stop the proxy at the next restart, and
	// the console locks itself while AuthError is set.
	if cfg.Admin.AuthFile != "" {
		auth, err := LoadAdminAuth(cfg.Admin.AuthFile)
		if errors.Is(err, os.ErrNotExist) {
			cfg.Admin.NeedsSetup = true
		} else if err != nil {
			cfg.Admin.AuthError = fmt.Sprintf("admin.auth_file: %v", err)
		} else {
			cfg.Admin.Users = auth.Users
		}
	}

	if err := validateAdmin(&cfg); err != nil {
		return nil, err
	}
	if err := validateLimits(&cfg.Limits); err != nil {
		return nil, err
	}
	if _, err := clientip.New(cfg.Proxy.Trusted, cfg.Proxy.ClientIPHeader); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// MaxRetentionDays bounds admin.max_age_days.
const MaxRetentionDays = 3650

// MaxAge is how old an event may get before it is deleted, or 0 when the
// history is limited by count instead.
func (a AdminConfig) MaxAge() time.Duration {
	if a.Retention != "age" {
		return 0
	}
	return time.Duration(a.MaxAgeDays) * 24 * time.Hour
}

// validateAdmin fails closed: an admin listener reachable beyond this
// machine must have a users file configured. One that is set but can't be
// loaded passes here, since the console then refuses every sign-in rather
// than running unauthenticated (see AuthError).
func validateAdmin(cfg *Config) error {
	if len(cfg.Admin.Allow) == 0 {
		return errors.New("admin.allow: an empty list would lock everyone out")
	}
	if _, err := clientip.ParseTrusted(cfg.Admin.Allow); err != nil {
		return fmt.Errorf("admin.allow: %w", err)
	}
	if r := cfg.Admin.Retention; r != "events" && r != "age" {
		return fmt.Errorf("admin.retention must be \"events\" or \"age\", not %q", r)
	}
	if d := cfg.Admin.MaxAgeDays; d < 1 || d > MaxRetentionDays {
		return fmt.Errorf("admin.max_age_days must be between 1 and %d", MaxRetentionDays)
	}
	if !isLoopbackAddr(cfg.Admin.Listen) && cfg.Admin.AuthFile == "" && len(cfg.Admin.Users) == 0 {
		return fmt.Errorf(
			"admin.listen (%q) is reachable beyond this machine but no admin.auth_file is configured — "+
				"run `loupe -setup-admin` first", cfg.Admin.Listen)
	}
	return nil
}

// isLoopbackAddr reports whether addr (a "host:port" listen address) is
// reachable only from this machine. An empty host (e.g. ":9090") means all
// interfaces, which is not loopback-only.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	return net.ParseIP(host).IsLoopback()
}

// persistPath is a file setting that defaults to def and is "off" to keep
// the data in memory only, which the rest of Loupe sees as "".
func persistPath(p, def string) string {
	switch p {
	case "":
		return def
	case "off":
		return ""
	}
	return p
}

func applyDefaults(cfg *Config) {
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	inData := func(name string) string { return filepath.Join(cfg.DataDir, name) }
	if cfg.Proxy.Trusted == nil {
		cfg.Proxy.Trusted = []string{"loopback"}
	}
	if cfg.Proxy.ClientIPHeader == "" {
		cfg.Proxy.ClientIPHeader = "X-Forwarded-For"
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.HMACSecretFile == "" {
		cfg.HMACSecretFile = inData("hmac_secret")
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "waf_pass"
	}
	if cfg.CookieTTL == 0 {
		cfg.CookieTTL = 86400
	}
	if cfg.Lumen.Work == 0 {
		cfg.Lumen.Work = 100000
	}
	if cfg.Lumen.PulseWork == 0 {
		cfg.Lumen.PulseWork = 20000
	}
	if cfg.Lumen.MemoryMB == 0 {
		cfg.Lumen.MemoryMB = 8
	}
	if cfg.Lumen.PulseMemoryMB == 0 {
		cfg.Lumen.PulseMemoryMB = 2
	}
	if cfg.Lumen.MaxMemoryMB == 0 {
		cfg.Lumen.MaxMemoryMB = 32
	}
	if cfg.Lumen.MaxLevel <= 0 || cfg.Lumen.MaxLevel > 4 {
		cfg.Lumen.MaxLevel = 4
	}
	if cfg.Lumen.MaxConcurrentChecks <= 0 {
		cfg.Lumen.MaxConcurrentChecks = 8
	}
	if cfg.ChallengePath == "" {
		cfg.ChallengePath = "/loupe/challenge"
	}
	if cfg.VerifyPath == "" {
		cfg.VerifyPath = "/loupe/verify"
	}
	if cfg.Admin.Listen == "" {
		cfg.Admin.Listen = "127.0.0.1:9090"
	}
	if cfg.Admin.Capacity == 0 {
		cfg.Admin.Capacity = 5000
	}
	if cfg.Admin.Retention == "" {
		cfg.Admin.Retention = "events"
	}
	if cfg.Admin.MaxAgeDays == 0 {
		cfg.Admin.MaxAgeDays = 30
	}
	if cfg.Admin.PruneLog == nil {
		on := true
		cfg.Admin.PruneLog = &on
	}
	if cfg.Admin.Allow == nil {
		cfg.Admin.Allow = []string{"loopback", "private"}
	}
	cfg.Admin.LogPath = persistPath(cfg.Admin.LogPath, inData("events.jsonl"))
	cfg.Reputation.SnapshotPath = persistPath(cfg.Reputation.SnapshotPath, inData("reputation.json"))
	if cfg.Admin.AuthFile == "" {
		cfg.Admin.AuthFile = inData("admin_auth.yaml")
	}
	if cfg.Admin.AuditPath == "" {
		cfg.Admin.AuditPath = inData("audit.jsonl")
	}
	if cfg.Admin.HistoryDir == "" {
		cfg.Admin.HistoryDir = inData("history")
	}
	if cfg.Admin.HistoryKeep <= 0 {
		cfg.Admin.HistoryKeep = 50
	} else if cfg.Admin.HistoryKeep == 1 {
		// A restore saves the file it replaces and then the restored one, so
		// keeping a single version would prune that safety copy at once.
		cfg.Admin.HistoryKeep = 2
	}
	if cfg.Bots.PolicyFile == "" {
		cfg.Bots.PolicyFile = inData("bots.yaml")
	}
	if cfg.Bots.RangesDir == "" {
		cfg.Bots.RangesDir = inData("ranges")
	}
	if cfg.Bots.RefreshHours <= 0 {
		cfg.Bots.RefreshHours = 24
	}
	if cfg.GoodBots.TTL == 0 {
		cfg.GoodBots.TTL = 3600
	}
	if cfg.Abuse.FailThreshold == 0 {
		cfg.Abuse.FailThreshold = 5
	}
	if cfg.Abuse.CooldownSeconds == 0 {
		cfg.Abuse.CooldownSeconds = 900
	}
	if cfg.Abuse.RateLimit.Rate == 0 {
		cfg.Abuse.RateLimit.Rate = 1.0
	}
	if cfg.Abuse.RateLimit.Burst == 0 {
		cfg.Abuse.RateLimit.Burst = 15
	}
	if cfg.Abuse.ClearanceBudget.DocRate == 0 {
		cfg.Abuse.ClearanceBudget.DocRate = 0.5
	}
	if cfg.Abuse.ClearanceBudget.DocBurst == 0 {
		cfg.Abuse.ClearanceBudget.DocBurst = 300
	}
	if cfg.Abuse.ClearanceBudget.AllRate == 0 {
		cfg.Abuse.ClearanceBudget.AllRate = 5
	}
	if cfg.Abuse.ClearanceBudget.AllBurst == 0 {
		cfg.Abuse.ClearanceBudget.AllBurst = 3000
	}
	if cfg.Hardening.RequestScore.Tier2 == 0 {
		cfg.Hardening.RequestScore.Tier2 = 2
	}
	if cfg.Hardening.RequestScore.Tier3 == 0 {
		cfg.Hardening.RequestScore.Tier3 = 4
	}
	if cfg.Hardening.RequestScore.Tier4 == 0 {
		cfg.Hardening.RequestScore.Tier4 = 9
	}
	if len(cfg.Hardening.AutomationArtifacts) == 0 {
		cfg.Hardening.AutomationArtifacts = defaultAutomationArtifacts
	}
	if len(cfg.Hardening.NativeFnNames) == 0 {
		cfg.Hardening.NativeFnNames = defaultNativeFnNames
	}
	if cfg.Reputation.HalfLifeHours == 0 {
		cfg.Reputation.HalfLifeHours = 6
	}
	if cfg.Reputation.SnapshotIntervalSeconds == 0 {
		cfg.Reputation.SnapshotIntervalSeconds = 300
	}
	if cfg.Reputation.Floors.Tier2 == 0 {
		cfg.Reputation.Floors.Tier2 = 4
	}
	if cfg.Reputation.Floors.Tier3 == 0 {
		cfg.Reputation.Floors.Tier3 = 12
	}
	if cfg.Reputation.Floors.Tier4 == 0 {
		cfg.Reputation.Floors.Tier4 = 40
	}
	if cfg.ASN.DBPath == "" {
		cfg.ASN.DBPath = inData("asn.aupldb")
	}
	if cfg.ASN.APIURL == "" {
		cfg.ASN.APIURL = DefaultAUPLAAPI
	}
	if cfg.ASN.TokenFile == "" {
		cfg.ASN.TokenFile = inData("aupldb_token")
	}
	if cfg.ASN.DatacenterASNsURL == "" {
		cfg.ASN.DatacenterASNsURL = DefaultDatacenterASNsURL
	}
	if cfg.ASN.DatacenterASNsFile == "" && cfg.ASN.DatacenterASNsURL != "off" {
		cfg.ASN.DatacenterASNsFile = inData("datacenter_asns.txt")
	}
	if cfg.ASN.DatacenterASNsRefreshHours <= 0 {
		cfg.ASN.DatacenterASNsRefreshHours = 168
	}
	if cfg.ASN.DatacenterCategories == nil {
		cfg.ASN.DatacenterCategories = []string{"hosting"}
	}
	if cfg.ASN.OverlayDir == "" {
		cfg.ASN.OverlayDir = filepath.Join(filepath.Dir(cfg.ASN.DBPath), "overlay")
	}
	if cfg.ASN.RefreshMinutes <= 0 {
		cfg.ASN.RefreshMinutes = 10
	}
	if cfg.Rules.File == "" {
		cfg.Rules.File = inData("rules.yaml")
	}
	if cfg.Limits.MaxURLBytes <= 0 {
		cfg.Limits.MaxURLBytes = 8192
	}
	if cfg.Limits.MaxQueryParams <= 0 {
		cfg.Limits.MaxQueryParams = 256
	}
	if len(cfg.Limits.AllowedMethods) == 0 {
		cfg.Limits.AllowedMethods = append([]string(nil), DefaultAllowedMethods...)
	}
	if cfg.BadIPs.URL == "" {
		cfg.BadIPs.URL = DefaultBadIPsURL
	}
	if cfg.BadIPs.CacheFile == "" {
		cfg.BadIPs.CacheFile = inData("badips.csv")
	}
	if cfg.BadIPs.RefreshHours <= 0 {
		cfg.BadIPs.RefreshHours = 24
	}
	if cfg.BadIPs.ChallengeAt <= 0 {
		cfg.BadIPs.ChallengeAt = 1
	}
	if cfg.BadIPs.BlockAt < 0 {
		cfg.BadIPs.BlockAt = 0
	}
	if cfg.Reputation.NonDatacenterMultiplier == 0 {
		cfg.Reputation.NonDatacenterMultiplier = 4
	}
}
