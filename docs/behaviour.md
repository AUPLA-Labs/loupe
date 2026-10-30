# Behaviour after clearance

A clearance cookie proves a browser passed a challenge once. Loupe also
watches what the cookie does afterwards, and flags page views that look
like a script driving it. Only document navigations count (requests with
`Sec-Fetch-Dest: document`). XHR and `fetch` calls (a mail client polling
for new messages, a file sync) are regular by design and never looked at.
Neither are assets, because Cloudflare may serve those from its cache
without Loupe seeing them.

| Signal | Fires when | Weight |
|---|---|---|
| `nav_too_regular` | The last 20 page views came at near-equal intervals (coefficient of variation under 0.1), averaging 20 seconds or less. A page that reloads itself every minute isn't flagged. | 2 |
| `nav_sustained_rate` | More than 60 page views within one minute. | 3 |
| `path_enumeration` | 10 or more page views in a row whose URL differs only in its last number, counting up by one (`/invoice/1000`, `/invoice/1001`…). | 3 |
| `no_referrer_chain` | 20 page views in a row opened directly (`Sec-Fetch-Site: none`), none by following a link. | 1 |

## Record only (default)

Each flagged page view's `ALLOW clearance` event carries the score and the
signals. The Overview's **Behaviour after clearance** panel sums them up by
signal and by client.

## Enforce

Turn on **Settings → Clearance → Behaviour after clearance: Enforce**
(`behaviour.enforce: true`, applies on restart). A page view scoring 3 or
more then:

- revokes the clearance, so copies of the cookie elsewhere stop working too;
- adds reputation pressure on the IP (as much as clearance abuse);
- is logged as `CHALLENGE clearance_behaviour` with the signals.

The visitor gets a fresh challenge. `no_referrer_chain` alone, or
`nav_too_regular` alone, never reaches 3.

## Before enforcing

When this was built (2026-10-24), the event log couldn't tell page views
from background requests, so the thresholds are conservative defaults, not
measured ones. Leave it on Record only for a while and check the panel.
Every page view it would have acted on is listed there, with its client.

## Limits

- At most 50,000 cookies are tracked at once, each forgotten after 30
  minutes without a page view. Each costs about 200 bytes.
- Private and loopback addresses aren't scored.
- Counts start over on restart.
