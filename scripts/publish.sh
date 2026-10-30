#!/bin/sh
# Copies a release built by scripts/release.sh to the folder the download
# site serves (get.auplalabs.com/loupe/), then points latest at it. The
# release's files go first and latest last, so a download never sees a
# version whose files aren't there yet.
#
#   scripts/publish.sh 0.1.0 [DEST]    (DEST default /var/www/get.auplalabs.com/loupe)
set -eu

version="${1:?usage: scripts/publish.sh VERSION [DEST]}"
dest="${2:-/var/www/get.auplalabs.com/loupe}"
cd "$(dirname "$0")/.."
[ -f "dist/$version/SHA256SUMS" ] || { echo "publish: no dist/$version; run scripts/release.sh $version" >&2; exit 1; }
(cd "dist/$version" && sha256sum -c SHA256SUMS >/dev/null) || { echo "publish: dist/$version doesn't match its checksums" >&2; exit 1; }

mkdir -p "$dest/$version"
cp "dist/$version"/* "$dest/$version/"
cp dist/install.sh "$dest/install.sh.new" && mv "$dest/install.sh.new" "$dest/install.sh"
printf '%s\n' "$version" >"$dest/latest.new" && mv "$dest/latest.new" "$dest/latest"
echo "published $version to $dest"
