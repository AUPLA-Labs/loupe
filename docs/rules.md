# Rules

Rules let you allow, block or challenge requests by what they look like,
before Loupe's own checks run. They live in one YAML file, `data/rules.yaml`
by default (set `rules.file` in the config to move it). Loupe re-reads the
file every 5 seconds, so a saved change is live within 5 seconds. No restart.

The dashboard's **Rules** page edits the same file: add, edit, reorder,
switch between log and enforce, test a request, and undo from the version
history. Its editor builds conditions one row at a time (field, operator,
value), joined by **And** within a group and **Or** between groups, and
saves them as an `any` list (see below). **Block…** on an IP profile adds an expiring block rule at the top.

## Example

```yaml
rules:
  # allow: skip every other check and proxy the request.
  - id: partner-api
    name: Partner API
    mode: enforce
    action: allow
    match:
      ips: [198.51.100.0/24]
      paths: [{prefix: /api/partner/}]

  # block: serve the block page, even on public paths and for cleared clients.
  - id: block-scanners
    mode: enforce
    action: block
    match:
      user_agents: [{glob: "*sqlmap*"}, {prefix: "nikto"}]
    except:
      ips: [203.0.113.7]            # our own scanner
    expires: 2027-01-31T00:00:00Z   # drops out by itself

  # challenge: raise the tier a visitor must pass (lumen_auto,
  # single_click or prism). Cleared clients, verified bots and trusted
  # networks still get through.
  - id: protect-login
    mode: enforce
    action: challenge
    tier: single_click
    match:
      methods: [POST]
      paths: [{exact: /login}]

  # log: only record the match on the event. Never changes the outcome.
  - id: watch-datacenters
    action: log
    match:
      datacenter: true

  # Tor exits and commercial VPNs straight to the Prism puzzle.
  - id: anonymisers
    mode: enforce
    action: challenge
    tier: prism
    match:
      classes: [tor_exit, vpn]
```

## Match fields

Fields in `match` are ANDed: every field you write must match. Values inside
one field are ORed. `except` takes the same fields; if it matches, the rule
does not apply. A rule needs at least one condition.

| Field | Matches | Notes |
|---|---|---|
| `ips` | Client address | Addresses or CIDRs, IPv4 or IPv6. A CIDR must be exact: `203.0.113.77/24` is rejected (use `203.0.113.0/24` or `203.0.113.77/32`). |
| `asns` | Network number | `[64496, 64497]`. ASN 0 is rejected. Never matches when the network is unknown. |
| `hosts` | `Host` header | `example.com` or `*.example.com` (subdomains only, not the apex). Write no port and no trailing dot. |
| `methods` | HTTP method | `[GET, POST]`, case-insensitive. |
| `paths` | URL path | List of `prefix`, `exact`, `glob` or `regex`. One per entry. Matched on the cleaned-up path, ignoring case (see below). |
| `user_agents` | `User-Agent` | Same four ops as `paths`. |
| `headers` | Request headers | `{name, op, value}`. Ops: `present`, `absent`, `equals`, `contains`, `regex`. `present` and `absent` take no value. |
| `query` | Query parameters | Same shape and ops as `headers`. |
| `countries` | Client country | Two-letter codes: where the address is used (the network's own geofeed when it publishes one, else the AUPLA database). Never matches an unknown country. |
| `registered_countries` | Registration country | Two-letter codes: where the address block is registered (RIR data). |
| `network_types` | Network type | Any of `isp`, `business`, `hosting`, `education_research`, `government_admin`. |
| `network_roles` | Network role | Any of `stub`, `access_provider`, `content_network`, `midsize_transit`, `major_transit`, `tier1_transit`. |
| `classes` | Address class | From the published lists Loupe fetches: any of `tor_exit`, `vpn`, `relay` (iCloud Private Relay), `crawler`, `fetcher` (verified bots, the latter acting for a person), `hosting` (a cloud's published ranges), `cdn`. Matches if the address is in any of them. |
| `lists` | Published list | List IDs, e.g. `tor_exits`, `mullvad`, `protonvpn`, `aws`, `googlebot` (System page, or `/v1/overlay.json`). Matches the list the address is named by first: relays, then Tor, VPNs, fetchers, crawlers, clouds, CDNs. |
| `datacenter` | Hosting/cloud network | `true` or `false`. True for a cloud's published ranges, the listed datacenter networks and networks of a type in `asn.datacenter_categories` (default `hosting`); never for Private Relay or verified crawler ranges. Never matches when the network is unknown. |
| `bad_ip_at_least` | Bad-IP lists | How many bad-IP lists name the address. A number; matches when at least that many do. |
| `bots` | Verified bot | Bot IDs, for example `googlebot`. Only bots whose address was verified. |
| `cleared` | Holds a valid clearance | `true` or `false`. |
| `anomalies` | Encoding tricks in the path | Any of `double_encoded`, `null_byte`, `backslash`, `dot_segment`, `invalid_utf8`, `overlong_utf8`. |

## And / Or groups

For conditions that a single `match` can't say, use `any`: a list of groups,
of which at least one must hold. Every condition in a group's `all` must
hold. A condition takes the same fields as `match` (normally one), and
`not: true` inverts it. This is what the dashboard writes.

```yaml
  - id: login-or-admin
    mode: enforce
    action: challenge
    tier: single_click
    any:
      - all:                         # POST to /login
          - paths: [{exact: /login}]
          - methods: [POST]
      - all:                         # or /admin from outside the office
          - paths: [{prefix: /admin}]
          - ips: [203.0.113.0/24]
            not: true
```

A rule may have `match`, `any` and `except` together: then `match` and one
group of `any` must hold, and `except` must not. A negated condition on a
fact Loupe doesn't know holds: `asns: [64496]` with `not: true` is true for
an address whose network is unknown. Opening a hand-written rule in the
dashboard and applying it rewrites its `match` and `except` as `any` groups,
with the same meaning.

Path and User-Agent ops: `prefix` and `exact` are literal; `glob` uses `*`
(any run of characters, `/` included) and `?` (one character); `regex` is Go
RE2 syntax, up to 1024 characters.

Other keys: `id` (required; lowercase letters, digits, `-`, `_`; unique),
`name`, `note`, `enabled: false` to switch a rule off, `mode`, `action`,
`tier` (challenge, or a rate limit with `then: challenge`), `limit`
(rate_limit only), `api` (api only), `expires`.

## Rate limits

`action: rate_limit` gives the requests a rule matches a budget:

```yaml
  - id: login-limit
    mode: enforce
    action: rate_limit
    limit:
      requests: 5          # allowed per period
      period: 1m           # 1s to 24h: 10s, 1m, 10m, 1h, 24h
      by: ip               # or header:X-Api-Key, cookie:session, query:token
      then: block          # block (429 with Retry-After) or challenge
    match:
      methods: [POST]
      paths: [{exact: /login}]
```

- A request within the budget is not decided by the rule: the rules below it
  run as if it didn't match. Only a request over the budget is acted on.
- `then: block` answers `429 Too Many Requests` with `Retry-After`, to
  everyone, cleared visitors included. A browser opening a page gets a
  "You're being rate limited" page in its language, with a countdown and a
  Try again button; other requests get a plain-text 429. `then: challenge` needs a `tier` and,
  like a challenge rule, doesn't re-challenge a cleared visitor.
- `by` picks who has a budget. With `header:`, `cookie:` or `query:`, a
  request without that value counts by IP, so leaving it out doesn't escape
  the limit. IPv6 clients are counted per /64, as everywhere in Loupe.
- In `mode: log` the rule counts and records its id on the event when the
  budget is exceeded, but limits nothing.
- The budget refills smoothly: 5 per minute is one more request every 12
  seconds, with up to 5 at once. Counters survive a save that doesn't change
  that rule's `requests`, `period` or `by`; changing them starts afresh, as
  does a restart.
- Requests Cloudflare answers from its cache never reach Loupe and aren't
  counted.
- One rule tracks at most 100,000 clients at a time; past that, new clients
  share one budget until old ones age out.

## API routes

Without a clearance, a request that isn't a page navigation (a script, an
app, `fetch` from another site) gets `403 clearance required`, because
there's no browser to show a challenge to. `action: api` serves a route to
such clients instead:

```yaml
  - id: asn-api
    mode: enforce
    action: api
    api:
      auth: backend_header    # or none
      header: Authorization   # the default
      realm: aupldb
      message: "missing or invalid token (terms: GET /v1/terms, token: POST /v1/tokens)"
    match:
      paths: [{prefix: /v1/asn}]

  - id: open-api
    mode: enforce
    action: api
    api: {auth: none}
    match:
      paths: [{exact: /healthz}, {prefix: /v1/badips}]
```

- `auth: backend_header`: the request must carry the header, with any
  value. Your backend checks the value; Loupe only requires it. Without it
  the answer is `401` with `WWW-Authenticate: Bearer` (plus `realm="…"` when
  set) and `message` as a plain-text body, or `{"error":"clearance_required"}`
  with `error: json`.
- `auth: loupe_keys`: the request must carry a key Loupe issued, in
  `X-API-Key` by default (with `header: Authorization`, send
  `Bearer lpk_…`). Keys are made and revoked on the dashboard's **API keys**
  page, shown once, and stored only as SHA-256 hashes in `api_keys.yaml`
  next to `rules.yaml`. A key can be limited to addresses or CIDRs (403 from
  elsewhere) and given its own requests-per-minute budget (429 over it). A
  revoked key stops working at once. Last use is saved every 5 minutes.
  An unknown key gets the same 401 as a missing one.
- `auth: none`: no credential. The route is open to scripts and apps.
- `allow_cookie` (default `true`): a browser holding a clearance passes
  without the header, so a web app on the same site can call its own API.
  Set it to `false` to require the header from browsers too.
- A CORS preflight (`OPTIONS` with `Access-Control-Request-Method`) is
  passed to the backend, which answers with its CORS policy.
- HTTP client libraries (curl, python-requests, Go, okhttp…) and an empty
  User-Agent are allowed on api routes. Scanners (sqlmap, nikto…) and your
  own `bad_bot_uas` patterns are still refused.
- An api rule doesn't end the search: block, allow and rate-limit rules
  below it still apply, as do Loupe's own blocks (repeat offenders, blocked
  networks, the bad-IP feed). Challenge rules below it are skipped, and a
  rate limit with `then: challenge` answers 429 instead, since an API client
  can't take a challenge. The first api rule that matches sets the policy.
- To limit each credential, add a rate limit by the same header, above or
  below the api rule:

  ```yaml
    - id: per-token
      mode: enforce
      action: rate_limit
      limit: {requests: 600, period: 1m, by: "header:Authorization"}
      match: {paths: [{prefix: /v1/asn}]}
  ```

- Loupe's own fetches (bad-IP feed, network database) come from this
  machine, and private addresses never meet any rule.

## Under attack mode

The shield button in the dashboard header turns on under attack mode:
every visitor without a clearance gets at least the chosen challenge
(Lumen, Single-click by default, or Prism), whatever their score. It turns
off by itself after 1, 6 or 24 hours, or stays on until turned off, and
survives a restart (`under_attack.json` next to `rules.yaml`). Optionally,
clearances issued before it was turned on must be earned again, once. A
visitor's next page view shows a challenge; background requests get 403
until then. Verified bots, allow rules, api routes and private addresses
are not affected. Every change is in the audit log.

## Log or enforce

`mode: log` records the rule's id on the event, as `logged_rules`, and
changes nothing. `mode: enforce` acts. A rule with no
`mode` is `log`, so a new rule is safe until you flip it. Watch the events for
a while, then set `mode: enforce`. A rule with `action: log` never changes the
outcome in either mode.

## Order

Rules run top to bottom and the first enforced match wins. That includes
`challenge`: if a challenge rule matches first, a later `allow` or `block`
never runs for that request. Put narrow rules (allow lists, exceptions)
above broad ones. Log-only matches never stop the search, but the search
does stop at the first enforced match: a log-only rule below it is not
checked and not recorded for that request. Put log-only rules you want to
see everywhere above your enforced ones.

## Expiry

`expires: 2027-01-31T00:00:00Z` (RFC 3339) switches a rule off from that
moment. Expired rules are ignored when matching and removed the next time the
file is saved from the dashboard.

## Things to know

- **Case.** Path matches ignore case: `/admin` also matches `/ADMIN`.
  User-Agent matches are case-sensitive; for a case-insensitive one, use a
  regex with `(?i)`: `{regex: "(?i)sqlmap"}`.
- **Cost.** A regex costs about 0.6 to 1.8 microseconds per request on top of
  the rest, and every rule is tried in order. Prefer `prefix`, `exact` and
  `glob`, which are far cheaper. 500 typical rules take about 16
  microseconds.
- **Private addresses.** Loopback (`127.0.0.0/8`, `::1`), private LAN
  (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`)
  addresses are never affected by any rule.
- **Paths are cleaned up first.** Rules see the path the way the backend
  most likely resolves it: decoded (twice if it was double-encoded),
  backslashes read as `/`, and `/./`, `/../` and repeated slashes resolved.
  So `//admin`, `/a/../admin`, `/x/%2e%2e/admin` and `/%2561dmin` all match a
  rule on `/admin`. What had to be undone is recorded as anomalies, which add
  to the request's suspicion score (+3 each, at most +6) and can be matched
  with `anomalies`.
- **Every rule trusts the proxy.** The client address comes from the
  header named in `proxy.client_ip_header`, believed only from the proxies
  in `proxy.trusted` (see [proxy.md](proxy.md)). A trusted proxy that passes
  on a visitor's forged value lets that visitor pick its own IP, ASN and
  datacenter facts, or claim a private address and skip all rules.
- **A broken file is not applied.** If `rules.yaml` has a YAML error or any rule
  fails validation (a bad regex, a duplicate id, a second `---` document, a
  CIDR with host bits), Loupe keeps the previous rules and logs the first
  error with the rule id and field. Fix the file and the next check applies it.
