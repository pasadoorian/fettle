#!/bin/sh
# Build fettle-<version>-1-any.pkg.tar.zst into $OUTDIR (default: dist/).
#
#   usage: packaging/arch/build.sh [OUTDIR]
#
# makepkg REFUSES TO RUN AS ROOT, and containers run as root by default — so the CI job
# for this needs an unprivileged build user or it fails with a message that reads like a
# permissions bug rather than a policy one.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
outdir="${1:-$here/dist}"
version=$("$here/packaging/version.sh")

if [ "$(id -u)" = 0 ]; then
    echo "packaging/arch/build.sh: makepkg will not run as root — use a normal user" >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# makepkg wants PKGBUILD and its source in one directory, and unpacks the tarball to
# $srcdir/$pkgname-$pkgver, so the archive has to contain that top-level name.
stage="$work/fettle-$version"
mkdir -p "$stage"
tar -c -C "$here" \
    --exclude='.git' --exclude='dist' --exclude='venv-*' --exclude='__pycache__' \
    --exclude='*.py[co]' . | tar -x -C "$stage"
tar -czf "$work/fettle-$version.tar.gz" -C "$work" "fettle-$version"

sed "s/^pkgver=.*/pkgver=$version/" "$here/packaging/arch/PKGBUILD" > "$work/PKGBUILD"

# --nodeps: makepkg checks depends against the LOCAL pacman database, which is empty on
# a Debian or Rocky build host. The dependency is still recorded in the built package;
# only the build-time check is skipped. Same reasoning as RPMBUILD_FLAGS=--nodeps.
( cd "$work" && makepkg --nodeps --noconfirm >"$work/makepkg.log" 2>&1 ) \
    || { cat "$work/makepkg.log" >&2; exit 1; }

mkdir -p "$outdir"
find "$work" -maxdepth 1 -name '*.pkg.tar.zst' -exec cp {} "$outdir/" \;
find "$outdir" -name "fettle-$version-*.pkg.tar.zst" -print
