# Request limits

Loupe refuses oversized and unusual requests before any other check, so
they never reach rules, challenges or the backend. Requests from loopback
and private addresses are exempt. Set them in the dashboard under
**Settings → Request limits**, or in `config.yaml` (applied on restart):

```yaml
limits:
  max_url_bytes: 8192          # path + query string; longer gets 414
  max_query_params: 256        # more gets 400
  max_body_bytes: 0            # 0 = no limit; larger gets 413
  allowed_methods: [GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS]  # others get 405
  upload_paths: [/upload/]     # path prefixes allowed a bigger body...
  upload_max_body_bytes: 0     # ...up to this (0 = no limit there)
```

- A body over the limit is refused at once when it says its size
  (`Content-Length`). One that doesn't (a chunked upload) is cut off at the
  limit as it is passed on, and the client gets 413.
- `upload_paths` are matched on the cleaned-up path (see the rules guide),
  case-sensitively.
- Each refusal is an event: `limit_url`, `limit_query`, `limit_body` or
  `limit_method`.

## Request smuggling

Go's HTTP server, which Loupe and Caddy both use, already refuses the
request shapes used for smuggling: conflicting `Content-Length` headers,
signed or negative lengths, unknown or stacked `Transfer-Encoding`, and
whitespace before a header's colon. A request with both `Transfer-Encoding`
and `Content-Length` is read by `Transfer-Encoding`, as RFC 9112 says, the
same way by Caddy and Loupe. Loupe usually listens behind a front proxy, which
re-frames every request it passes on. `TestGoServerRejectsSmuggling` pins this, so a
Go upgrade that changed it would fail the tests.
