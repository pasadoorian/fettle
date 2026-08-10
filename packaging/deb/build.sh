#!/bin/sh
# Build fettle-<version>_all.deb into $OUTDIR (default: dist/).
#
#   usage: packaging/deb/build.sh [OUTDIR]
#
# Deliberately `dpkg-deb --build` over a staged tree rather than debhelper: fettle has
# no build step and no dependencies, so a full debian/ directory would be ceremony
# around one `cp -R`. The tree itself comes from packaging/install.sh, which the .rpm
# and the Arch package also use, so all three ship the identical layout.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
outdir="${1:-$here/dist}"
version=$("$here/packaging/version.sh")

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# mktemp -d gives 0700 and dpkg-deb preserves the staging root's mode, so without this
# the package ships `./` as drwx------ — a package that carries mode 0700 for the
# filesystem root. Caught by reading `dpkg-deb -c` output rather than by it failing.
chmod 755 "$work"

sh "$here/packaging/install.sh" "$work"
mkdir -p "$work/DEBIAN"

# Architecture: all — fettle is pure python, so one package serves every architecture.
# Depends names an interpreter and nothing else, which is the zero-dependency property
# stated somewhere a machine will check it. The alternatives matter: Ubuntu 22.04's
# `python3` is 3.10, too old for fettle, but it has python3.11 in universe — so
# `python3 (>= 3.11)` alone would refuse to install on a system that runs fettle fine.
cat > "$work/DEBIAN/control" <<EOF
Package: fettle
Version: $version
Section: admin
Priority: optional
Architecture: all
Depends: python3 (>= 3.11) | python3.11 | python3.12 | python3.13
Maintainer: Paul Asadoorian <paul@rihackers.com>
Homepage: https://github.com/pasadoorian/fettle
Description: Cross-distribution Linux maintenance and supply-chain tool
 One command surface keeps a machine updated and clean, audits where its
 software came from and whether it has been tampered with, and scans the
 firmware and boot chain.
 .
 Pure standard library: it needs python3 and nothing else.
EOF

# Debian keeps licensing in the package's doc directory under this name. install.sh has
# already put a LICENSE there for every distro; this is the Debian-conventional copy.
cp "$work/usr/share/doc/fettle/LICENSE" "$work/usr/share/doc/fettle/copyright"

mkdir -p "$outdir"
# `--root-owner-group` so the package owns its files as root:root even though the build
# runs unprivileged. Without it every path in the .deb is owned by whoever built it.
dpkg-deb --root-owner-group --build "$work" "$outdir/fettle_${version}_all.deb" >/dev/null
echo "$outdir/fettle_${version}_all.deb"
