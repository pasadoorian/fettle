#!/bin/sh
# Build fettle-<version>-1.noarch.rpm into $OUTDIR (default: dist/).
#
#   usage: packaging/rpm/build.sh [OUTDIR]
#
# Makes the source tarball the spec expects, then rpmbuild's it in a private topdir so
# nothing lands in ~/rpmbuild.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
outdir="${1:-$here/dist}"
version=$("$here/packaging/version.sh")

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work"/{SOURCES,SPECS,BUILD,RPMS,SRPMS}

# The tarball has to unpack to fettle-<version>/ for %setup to find it. Copy rather than
# archive-in-place so build droppings and the dist/ directory stay out of the source.
stage="$work/fettle-$version"
mkdir -p "$stage"
tar -c -C "$here" \
    --exclude='.git' --exclude='dist' --exclude='venv-*' --exclude='__pycache__' \
    --exclude='*.py[co]' . | tar -x -C "$stage"
tar -czf "$work/SOURCES/fettle-$version.tar.gz" -C "$work" "fettle-$version"

# RPMBUILD_FLAGS=--nodeps is how you build this on a machine that is not RPM-based:
# rpmbuild checks BuildRequires against the local rpm database, and on Arch or Debian
# that database is empty, so `python3 >= 3.11` cannot be satisfied even though python3
# is plainly installed. It is a property of the build host, not of the spec — CI builds
# in a Rocky container where the check passes for real.
# shellcheck disable=SC2086
rpmbuild -bb "$here/packaging/rpm/fettle.spec" \
    --define "_topdir $work" \
    --define "_fettle_version $version" \
    ${RPMBUILD_FLAGS:-} \
    >"$work/rpmbuild.log" 2>&1 || { cat "$work/rpmbuild.log" >&2; exit 1; }

mkdir -p "$outdir"
find "$work/RPMS" -name '*.rpm' -exec cp {} "$outdir/" \;
find "$outdir" -name "fettle-$version-*.rpm" -print
