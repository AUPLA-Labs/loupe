#!/bin/sh
# Builds a Loupe release into dist/: static linux/amd64 and linux/arm64
# binaries with their SHA-256 sums in dist/VERSION, plus dist/latest and
# dist/install.sh. scripts/publish.sh puts it online.
#
#   scripts/release.sh 0.1.0
set -eu

version="${1:?usage: scripts/release.sh VERSION}"
case "$version" in
*[!0-9A-Za-z.+-]*) echo "release: bad version \"$version\"" >&2; exit 1 ;;
esac
cd "$(dirname "$0")/.."
if [ -n "$(git status --porcelain)" ]; then
	echo "release: commit or stash your changes first; a release is built from a commit" >&2
	exit 1
fi
GO="${GO:-go}"
command -v "$GO" >/dev/null 2>&1 || GO=/usr/local/go/bin/go

out="dist/$version"
rm -rf "$out"
mkdir -p "$out"
for arch in amd64 arm64; do
	echo "building linux/$arch"
	CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$GO" build -trimpath \
		-ldflags "-s -w -X github.com/AUPLA-Labs/loupe/internal/version.Version=$version" \
		-o "$out/loupe-linux-$arch" ./cmd/loupe
done
(cd "$out" && sha256sum loupe-linux-* >SHA256SUMS)
printf '%s\n' "$version" >dist/latest
cp scripts/install.sh dist/install.sh
echo "dist/$version is ready (commit $(git rev-parse --short HEAD)). Publish with: scripts/publish.sh $version"
