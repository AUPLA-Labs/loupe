# Loupe

Loupe protects a website from bots and abuse. It sits between your reverse
proxy and your site, lets people and good bots through, and challenges or
blocks the rest. A dashboard shows what it sees and lets you write rules.

```sh
curl -fsSL https://get.auplalabs.com/loupe/install.sh | sh
```

Linux with systemd, amd64 or arm64. The [install guide](docs/install.md)
covers what that does, the first sign-in, upgrades and uninstalling.

## Docs

- [Installing](docs/install.md)
- [Running behind a proxy](docs/proxy.md): Caddy, nginx, Apache, HAProxy,
  Traefik, Cloudflare
- [Rules](docs/rules.md)
- [Limits](docs/limits.md)
- [Behaviour](docs/behaviour.md)
- [`config.example.yaml`](config.example.yaml) is what a new install starts
  from; every setting it leaves out has a default.

## Building

Go 1.26 or newer.

```sh
make build                    # ./loupe
make test
make release VERSION=0.1.0    # static builds and checksums in dist/
```

## License

Loupe is free for noncommercial use under the
[PolyForm Noncommercial License 1.0.0](LICENSE): personal sites, hobby
projects, research, education, charities and public bodies. For commercial
use, contact AUPLA Labs at https://auplalabs.com.
