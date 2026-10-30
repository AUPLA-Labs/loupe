# Installing Loupe

Loupe sits between your reverse proxy and your site:

```
visitor → your proxy (HTTPS) → Loupe → your site
```

You need:

- Linux with systemd, on amd64 or arm64. Without systemd, see
  [Other init systems](#other-init-systems).
- A reverse proxy in front: Caddy, nginx, Apache, HAProxy, Traefik or a
  Cloudflare Tunnel.
- The address your site listens on, e.g. `http://127.0.0.1:3000`.

## Install

```sh
curl -fsSL https://get.auplalabs.com/loupe/install.sh | sh
```

The script downloads the Loupe build for your machine, checks its SHA-256
sum, and runs `loupe install` with sudo. That asks one question, the
address of your site, then sets Loupe up as a service and starts it.

To install without questions, pass the answers along:

```sh
curl -fsSL https://get.auplalabs.com/loupe/install.sh | sh -s -- --backend http://127.0.0.1:3000 --yes
```

| Option | Default | |
|---|---|---|
| `--backend URL` | asked | Your site. |
| `--listen ADDR` | `127.0.0.1:8080` | Where your proxy reaches Loupe. |
| `--admin-listen ADDR` | `0.0.0.0:9090` | Where the dashboard listens. |
| `--yes` | | Don't ask. A busy default port moves to the next free one. |

If port 8080 or 9090 is taken, the installer offers the next free one. A
port you name yourself has to be free.

It creates:

| | |
|---|---|
| `/usr/local/bin/loupe` | The program. |
| `/etc/loupe/config.yaml` | Settings. Short; every other setting has a default. |
| `/var/lib/loupe/` | Everything Loupe keeps: users, lists, events. |
| `/etc/systemd/system/loupe.service` | The service, running as user `loupe`. |
| user and group `loupe` | |

## Point your proxy at Loupe

Send your site's traffic to `http://127.0.0.1:8080` (or the port the
installer chose) instead of to your site. Your proxy has to pass `Host`,
`X-Forwarded-For` and `X-Forwarded-Proto`; [proxy.md](proxy.md) has a
working setup for each proxy, including Cloudflare in front.

## Create the first admin

The installer ends with a link like
`http://192.168.1.20:9090/setup/4f1c…`. Open it from a browser on the same
network, choose a username and password, and sign in. The link works once.
If you lose it before using it: `journalctl -u loupe | grep setup`.

The dashboard answers only loopback and private networks. On a VPS with no
private network, tunnel to it over SSH and use the `127.0.0.1` link:

```sh
ssh -L 9090:127.0.0.1:9090 you@your-server
```

To reach it over Tailscale or a VPN instead, add that range to
`admin.allow` in `/etc/loupe/config.yaml`, e.g.
`allow: [loopback, private, 100.64.0.0/10]`, and restart Loupe. Don't
publish the dashboard through your proxy unless you also put HTTPS and
access control in front of it.

## Day to day

| | |
|---|---|
| Logs | `journalctl -u loupe -f` |
| Restart after editing the config | `sudo systemctl restart loupe` |
| Change ports | `listen` and `admin.listen` in `/etc/loupe/config.yaml`, then restart |
| Users | `sudo -u loupe loupe -setup-admin list-users -config /etc/loupe/config.yaml`; also `add-user NAME admin`, `set-password NAME`, `reset-2fa NAME`, `remove-user NAME` |
| Version | `loupe -version` |

## Upgrade

Run the install command again. It replaces the program and the service
file and restarts Loupe; your config and data stay as they are. To pick a
version instead of the latest:

```sh
curl -fsSL https://get.auplalabs.com/loupe/install.sh | LOUPE_VERSION=0.1.0 sh
```

## Uninstall

```sh
sudo systemctl disable --now loupe
sudo rm /etc/systemd/system/loupe.service /usr/local/bin/loupe
sudo systemctl daemon-reload
sudo rm -r /etc/loupe /var/lib/loupe   # your settings and data
sudo userdel loupe
```

Point your proxy back at your site first.

## Other init systems

Download `loupe-linux-amd64` or `loupe-linux-arm64` from
`https://get.auplalabs.com/loupe/<version>/` (the current version is in
`https://get.auplalabs.com/loupe/latest`) and check it against
`SHA256SUMS` in the same folder. Then:

```sh
sudo install -m 755 loupe-linux-amd64 /usr/local/bin/loupe
sudo mkdir -p /etc/loupe /var/lib/loupe
loupe install --print-config --backend http://127.0.0.1:3000 | sudo tee /etc/loupe/config.yaml
```

Create a user for Loupe, give it `/etc/loupe` and `/var/lib/loupe`, and have
your init system run `/usr/local/bin/loupe /etc/loupe/config.yaml` as that
user, with `/var/lib/loupe` as the working directory. The setup link
appears in Loupe's output.
