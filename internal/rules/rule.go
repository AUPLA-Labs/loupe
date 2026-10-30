// Package rules is Loupe's operator-written rule engine: a YAML file of
// match conditions and actions, compiled once into a form that is cheap to
// evaluate on every request.
package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode says whether a matching rule is enforced or only recorded.
type Mode string

// Action is what a matching rule does.
type Action string

const (
	ModeLog     Mode = "log"
	ModeEnforce Mode = "enforce"

	ActionAllow     Action = "allow"
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge"
	ActionLog       Action = "log"
	ActionRateLimit Action = "rate_limit"
	ActionAPI       Action = "api"
)

// Rule is one entry of rules.yaml.
type Rule struct {
	ID      string     `yaml:"id" json:"id"`
	Name    string     `yaml:"name,omitempty" json:"name,omitempty"`
	Enabled *bool      `yaml:"enabled,omitempty" json:"enabled,omitempty"` // nil = true
	Mode    Mode       `yaml:"mode,omitempty" json:"mode,omitempty"`       // "" = log
	Match   Match      `yaml:"match,omitempty" json:"match"`
	Any     []Group    `yaml:"any,omitempty" json:"any,omitempty"` // and one of these groups, when set
	Except  *Match     `yaml:"except,omitempty" json:"except,omitempty"`
	Action  Action     `yaml:"action" json:"action"`
	Limit   *Limit     `yaml:"limit,omitempty" json:"limit,omitempty"`     // rate_limit only
	API     *APIPolicy `yaml:"api,omitempty" json:"api,omitempty"`         // api only
	Tier    string     `yaml:"tier,omitempty" json:"tier,omitempty"`       // challenge, or rate_limit with then: challenge: lumen_auto | single_click | prism
	Expires *time.Time `yaml:"expires,omitempty" json:"expires,omitempty"` // RFC 3339
	Note    string     `yaml:"note,omitempty" json:"note,omitempty"`
}

// Match is a set of conditions. Fields AND together; values within a field OR.
type Match struct {
	IPs        []string      `yaml:"ips,omitempty" json:"ips,omitempty"` // addresses or CIDRs, v4 or v6
	ASNs       []uint        `yaml:"asns,omitempty" json:"asns,omitempty"`
	Hosts      []string      `yaml:"hosts,omitempty" json:"hosts,omitempty"` // exact, or "*.example.com" (subdomains only)
	Methods    []string      `yaml:"methods,omitempty" json:"methods,omitempty"`
	Paths      []PathMatch   `yaml:"paths,omitempty" json:"paths,omitempty"`
	Headers    []HeaderMatch `yaml:"headers,omitempty" json:"headers,omitempty"`
	Query      []HeaderMatch `yaml:"query,omitempty" json:"query,omitempty"`
	UserAgents []PathMatch   `yaml:"user_agents,omitempty" json:"user_agents,omitempty"`
	Countries  []string      `yaml:"countries,omitempty" json:"countries,omitempty"` // ISO 3166 alpha-2, where the address is used
	// The network and what published lists say about the address (AUPLA
	// database and overlay), see NetworkTypes, NetworkRoles, AddressClasses.
	RegisteredCountries []string `yaml:"registered_countries,omitempty" json:"registered_countries,omitempty"` // ISO 3166 alpha-2 of the RIR registration
	NetworkTypes        []string `yaml:"network_types,omitempty" json:"network_types,omitempty"`
	NetworkRoles        []string `yaml:"network_roles,omitempty" json:"network_roles,omitempty"`
	Classes             []string `yaml:"classes,omitempty" json:"classes,omitempty"` // any of them
	Lists               []string `yaml:"lists,omitempty" json:"lists,omitempty"`     // overlay list IDs, e.g. mullvad, tor_exits
	Datacenter          *bool    `yaml:"datacenter,omitempty" json:"datacenter,omitempty"`
	BadIPAtLeast        int      `yaml:"bad_ip_at_least,omitempty" json:"bad_ip_at_least,omitempty"`
	Bots                []string `yaml:"bots,omitempty" json:"bots,omitempty"` // verified bot IDs
	Cleared             *bool    `yaml:"cleared,omitempty" json:"cleared,omitempty"`
	Anomalies           []string `yaml:"anomalies,omitempty" json:"anomalies,omitempty"` // path anomalies, see PathAnomalies
}

// PathAnomalies are the encoding tricks Loupe undoes before matching a path,
// each reported as a fact a rule can match: %25xx double encoding, a NUL
// byte, a backslash, a /./ or /../ segment, invalid UTF-8 and overlong UTF-8.
// NetworkTypes are the kinds of organisation a network can be run by.
var NetworkTypes = []string{"isp", "business", "hosting", "education_research", "government_admin"}

// NetworkRoles are a network's places in the routing hierarchy.
var NetworkRoles = []string{"stub", "access_provider", "content_network", "midsize_transit", "major_transit", "tier1_transit"}

// AddressClasses are what the overlay's published lists say an address is:
// a Tor exit, a VPN server, a privacy relay (iCloud Private Relay), a
// verified crawler or user-triggered fetcher, a cloud's range, a CDN edge.
var AddressClasses = []string{"tor_exit", "vpn", "relay", "crawler", "fetcher", "hosting", "cdn"}

var PathAnomalies = []string{"double_encoded", "null_byte", "backslash", "dot_segment", "invalid_utf8", "overlong_utf8"}

// Limit is a rate_limit rule's budget: Requests per Period for each value of
// By. A request within the budget goes on to the next rule; one over it gets
// Then.
type Limit struct {
	Requests int    `yaml:"requests" json:"requests"`
	Period   string `yaml:"period" json:"period"`                 // Go duration, 1s to 24h: "10s", "1m", "1h"
	By       string `yaml:"by,omitempty" json:"by,omitempty"`     // ip (default) | header:<name> | cookie:<name> | query:<name>
	Then     Action `yaml:"then,omitempty" json:"then,omitempty"` // block (default, a 429) | challenge
}

// APIPolicy is an api rule's route policy. Matching requests are served to
// non-browser clients without the browser challenge: a client passes with a
// clearance cookie (when AllowCookie), or with the credential Auth asks for.
// Blocks and rate limits still apply.
type APIPolicy struct {
	Auth        string `yaml:"auth" json:"auth"`                                     // backend_header | loupe_keys | none
	Header      string `yaml:"header,omitempty" json:"header,omitempty"`             // default Authorization (backend_header), X-API-Key (loupe_keys)
	AllowCookie *bool  `yaml:"allow_cookie,omitempty" json:"allow_cookie,omitempty"` // nil = true: a cleared browser passes
	Error       string `yaml:"error,omitempty" json:"error,omitempty"`               // text (default) | json
	Message     string `yaml:"message,omitempty" json:"message,omitempty"`           // text 401 body
	Realm       string `yaml:"realm,omitempty" json:"realm,omitempty"`               // WWW-Authenticate realm
}

// API auth modes.
const (
	APIAuthBackendHeader = "backend_header"
	APIAuthLoupeKeys     = "loupe_keys"
	APIAuthNone          = "none"
)

// CookieAllowed reports whether a clearance cookie passes the route.
func (p *APIPolicy) CookieAllowed() bool {
	return p.AllowCookie == nil || *p.AllowCookie
}

// Group is one alternative of a rule's any list: every condition in it must
// hold. This is the shape the dashboard's rule builder writes.
type Group struct {
	All []Condition `yaml:"all" json:"all"`
}

// Condition is one line of a group: a Match (normally of a single field),
// inverted when Not is set. A negated test on a fact Loupe doesn't know, such
// as the network of an unknown address, holds.
type Condition struct {
	Match `yaml:",inline"`
	Not   bool `yaml:"not,omitempty" json:"not,omitempty"`
}

// PathMatch tests a path or User-Agent. Exactly one field is set.
type PathMatch struct {
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Exact  string `yaml:"exact,omitempty" json:"exact,omitempty"`
	Glob   string `yaml:"glob,omitempty" json:"glob,omitempty"`
	Regex  string `yaml:"regex,omitempty" json:"regex,omitempty"`
}

// HeaderMatch tests a request header or query parameter.
type HeaderMatch struct {
	Name  string `yaml:"name" json:"name"`
	Op    string `yaml:"op" json:"op"` // present | absent | equals | contains | regex
	Value string `yaml:"value,omitempty" json:"value,omitempty"`
}

// File is the shape of rules.yaml.
type File struct {
	Rules []Rule `yaml:"rules" json:"rules"`
}

// Parse decodes a rules file. Unknown keys are errors, so a typo like
// "acton:" is reported instead of silently producing a rule with no action.
// A second YAML document (after ---) is an error: it would otherwise be
// dropped without a word. An empty file is an empty rule set. Parse does not
// validate; Compile does.
func Parse(data []byte) ([]Rule, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("rules.yaml must hold one YAML document")
	}
	return f.Rules, nil
}

// IsEnabled reports whether the rule is switched on. A rule with no
// enabled key is enabled.
func (r Rule) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

// RuleError names the rule and the YAML field that failed validation, so an
// editor can point at it.
type RuleError struct {
	Index int    // position in the file, from 0
	ID    string // empty when the rule has no usable id
	Field string // YAML path, for example match.paths[1].regex
	Msg   string
}

func (e *RuleError) Error() string {
	if e.ID == "" {
		return fmt.Sprintf("rule #%d: %s: %s", e.Index+1, e.Field, e.Msg)
	}
	return fmt.Sprintf("rule %q: %s: %s", e.ID, e.Field, e.Msg)
}
