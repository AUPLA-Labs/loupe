#!/bin/sh
# Installs Loupe on this machine: downloads the binary for it, checks it
# against the release's SHA-256 sums and runs `loupe install`, which sets up
# the service. Running it again upgrades Loupe and keeps its config.
#
#   curl -fsSL https://get.auplalabs.com/loupe/install.sh | sh
#   curl -fsSL https://get.auplalabs.com/loupe/install.sh | sh -s -- --backend http://127.0.0.1:3000 --yes
#
# Arguments go to `loupe install` (--backend, --listen, --admin-listen, --yes).
# LOUPE_VERSION picks a release instead of the latest; LOUPE_BASE_URL another
# download server.
set -eu

base="${LOUPE_BASE_URL:-https://get.auplalabs.com/loupe}"

die() {
	printf 'loupe: %s\n' "$*" >&2
	exit 1
}

[ "$(uname -s)" = Linux ] || die "Loupe runs on Linux; this is $(uname -s)"
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "no Loupe build for $(uname -m) yet (there are amd64 and arm64)" ;;
esac

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	die "needs curl or wget to download"
fi
command -v sha256sum >/dev/null 2>&1 || die "needs sha256sum to check the download"

tmp=$(mktemp -d) # in $TMPDIR, else /tmp
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' INT TERM

version="${LOUPE_VERSION:-}"
if [ -z "$version" ]; then
	fetch "$base/latest" "$tmp/latest" || die "can't reach $base"
	version=$(tr -d ' \r\n' <"$tmp/latest")
fi
case "$version" in
"" | *[!0-9A-Za-z.+-]*) die "bad version \"$version\"" ;;
esac

bin="loupe-linux-$arch"
printf 'Downloading Loupe %s for %s…\n' "$version" "$arch" >&2
fetch "$base/$version/$bin" "$tmp/$bin" || die "can't download $base/$version/$bin"
fetch "$base/$version/SHA256SUMS" "$tmp/SHA256SUMS" || die "can't download the checksums"
sum=$(grep "  $bin\$" "$tmp/SHA256SUMS") || die "no checksum for $bin in this release"
(cd "$tmp" && printf '%s\n' "$sum" | sha256sum -c - >/dev/null 2>&1) || die "checksum mismatch for $bin; not installing it"
chmod 755 "$tmp/$bin"
# Hardened servers often mount /tmp noexec; say so instead of failing with a
# bare "Permission denied".
"$tmp/$bin" -version >/dev/null 2>&1 || die "can't run programs from $tmp (is it mounted noexec?); rerun with TMPDIR set to a folder that allows it, e.g. TMPDIR=\$HOME"

# Under `curl | sh` this script is stdin, so the installer's questions read
# the terminal instead; with no terminal it asks nothing.
in=/dev/null
if (: </dev/tty) 2>/dev/null; then
	in=/dev/tty
fi
if [ "$(id -u)" -eq 0 ]; then
	"$tmp/$bin" install "$@" <"$in"
else
	command -v sudo >/dev/null 2>&1 || die "run this as root (sudo isn't installed)"
	sudo "$tmp/$bin" install "$@" <"$in"
fi
