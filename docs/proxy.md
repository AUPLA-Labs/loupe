# Running Loupe behind a proxy

Loupe speaks plain HTTP and sits between a front proxy and your site:

```
visitor → front proxy (HTTPS) → Loupe → your site
```

New to Loupe? [install.md](install.md) sets it up; this page is about the
proxy in front.

Any reverse proxy works as the front proxy: Caddy, nginx, Apache, HAProxy,
Traefik, a Cloudflare Tunnel. Loupe doesn't depend on any of them. What
matters is that the proxy does four things, and some proxies need telling.

## What the front proxy must do

1. **Terminate HTTPS.** Loupe has no TLS of its own.
2. **Pass the visitor's `Host` header through unchanged.** Loupe's cookies,
   rules, events and robots.txt handling use it, and your site needs it to
   know which site was asked for. Caddy, HAProxy and Traefik do this by
   default. **nginx and Apache don't**: without the setting shown below, every
   request looks like it was for `127.0.0.1:8080`.
3. **Send the visitor's address** in a header, usually `X-Forwarded-For`,
   and tell Loupe which proxies to believe (below). Without it, every
   visitor looks like the proxy and Loupe enforces nothing.
4. **Send `X-Forwarded-Proto`** (`https` or `http`). Without it Loupe treats
   every visit as plain HTTP: its cookies lose the `Secure` flag, and your
   site may build `http://` links or redirect in a loop.

Keep the proxy's idle keep-alive to Loupe under 10 minutes; Loupe closes
idle connections after that. Every common proxy's default is well under it.

Your site, behind Loupe, can be any HTTP server. Loupe passes the visitor's
`Host` on to it, so it must answer to that name.

## Telling Loupe which proxies to believe

Every rule, limit and challenge depends on knowing the visitor's address,
and that address is in a header the front proxy sets. Loupe has to know
which proxies to believe, because anyone can send that header.

```yaml
proxy:
  trusted: [loopback]                # who may tell Loupe the visitor's address
  client_ip_header: X-Forwarded-For  # where they put it
```

- **`trusted`** holds addresses, CIDRs, or the presets `loopback`
  (`127.0.0.0/8`, `::1`), `private` (`10/8`, `172.16/12`, `192.168/16`,
  `fc00::/7`) and `cloudflare` (Cloudflare's published ranges). Unset means
  `[loopback]`. `[]` trusts nobody: every visitor is the socket address.
- **`client_ip_header`** is the header a trusted proxy puts the visitor's
  address in. `X-Forwarded-For` is read from the right, skipping trusted
  hops, so whatever a visitor writes at the front of it is ignored. A
  single-value header such as `CF-Connecting-IP` or `X-Real-IP` works the
  same way.

From a peer that isn't trusted, Loupe ignores the client-IP header and
`X-Forwarded-Proto`, and strips them before the request reaches your site.
So it's safe for Loupe to listen on all interfaces. Binding to `127.0.0.1`
is still tidier when the proxy is on the same machine.

`X-Forwarded-Proto` from a trusted proxy tells Loupe whether the visitor
used HTTPS. Loupe passes it on to your site and sets its cookies `Secure`
only then.

Changes take effect on restart.

## Setups

Each one assumes the proxy and Loupe share a machine and Loupe listens on
`127.0.0.1:8080`. The YAML is the `proxy:` block in Loupe's `config.yaml`.

### Caddy

The defaults work. Caddy passes `Host` and sets `X-Forwarded-For` and
`X-Forwarded-Proto` itself:

```
example.com {
	reverse_proxy 127.0.0.1:8080
}
```

### nginx

The defaults work, but nginx needs all three headers set. The `Host` line
is the one most often missed:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Raise `client_max_body_size` if your site takes large uploads; Loupe has its
own limit (`limits.max_body_bytes`).

### Apache

The defaults work. `mod_proxy` adds `X-Forwarded-For` itself, but
`ProxyPreserveHost` is off by default and `X-Forwarded-Proto` needs
`mod_headers`:

```apache
ProxyPreserveHost On
RequestHeader set X-Forwarded-Proto "https"
ProxyPass        / http://127.0.0.1:8080/
ProxyPassReverse / http://127.0.0.1:8080/
```

Use `"http"` instead in a plain-HTTP virtual host.

### HAProxy

The defaults work. `option forwardfor` adds `X-Forwarded-For`; the proto
header has to be set:

```
backend loupe
    option forwardfor
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-Proto http unless { ssl_fc }
    server loupe 127.0.0.1:8080
```

### Traefik, or any proxy in a Docker network

Traefik passes `Host` and sets `X-Forwarded-For` and `X-Forwarded-Proto` by
default. In Docker, the proxy reaches Loupe from a container address, not
loopback, so trust that network:

```yaml
proxy:
  trusted: [loopback, private]   # or just the Docker network, e.g. 172.18.0.0/16
```

### Cloudflare in front of your proxy

Your proxy sees Cloudflare's edge, not the visitor. Either:

- Let the proxy trust Cloudflare and append to `X-Forwarded-For`, and trust
  Cloudflare in Loupe too:

  ```yaml
  proxy:
    trusted: [loopback, cloudflare]
  ```

  For Caddy that means `trusted_proxies static <Cloudflare's ranges>` in its
  global `servers` block. Without it, Caddy replaces the header with the
  edge's address, and every visitor looks like Cloudflare. nginx's
  `$proxy_add_x_forwarded_for` already appends, so it needs nothing extra.

- Or have the proxy pass on `CF-Connecting-IP` only from Cloudflare's ranges
  (and overwrite it otherwise), and read that:

  ```yaml
  proxy:
    trusted: [loopback]
    client_ip_header: CF-Connecting-IP
  ```

### Cloudflare Tunnel

`cloudflared` connects from loopback, and Cloudflare sets
`CF-Connecting-IP` at its edge:

```yaml
proxy:
  trusted: [loopback]
  client_ip_header: CF-Connecting-IP
```

## Spotting a wrong setup

- **Every event shows the same host, `127.0.0.1:8080`, or your site shows
  the wrong page.** The proxy isn't passing `Host` on. See nginx and Apache
  above.
- **Cookies aren't `Secure`, or your site redirects in a loop.** The proxy
  isn't sending `X-Forwarded-Proto`.
- **Every event shows your proxy's address** (often `127.0.0.1`). The
  proxy isn't sending the header Loupe reads. Loupe logs this once, at the
  first such request:
  `proxy: a request from trusted proxy … carried no usable …`.
  Loopback and private addresses are exempt from rules and limits, so in
  this state **Loupe enforces nothing**. Fix it before going live.
- **Every event shows a Cloudflare or Docker address.** A hop between the
  visitor and Loupe isn't in `trusted`. Add it, or have it pass the
  visitor's address on.
- **Visitors can choose their address.** Check with
  `curl -H 'X-Forwarded-For: 203.0.113.1' https://your.site/` (or your
  `client_ip_header`). The event must show your own address, not
  `203.0.113.1`. If it shows `203.0.113.1`, something in `trusted` passes
  the header on unchecked.
