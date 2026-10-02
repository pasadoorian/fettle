#!/bin/sh
# Package an already-built binary into its release archives.
#
#   usage: packaging/binary/archive.sh [OUTDIR]
#
#   dist/fettle-<version>-linux-x86_64.tar.gz
#   dist/fettle-<version>-linux-x86_64.zip
#
# Expects $OUTDIR/fettle to exist — packaging/binary/build.sh puts it there, and
# smoke-tests it before this runs.
#
# Unlike the zipapp archive, there is no launcher script here: the binary IS the
# executable and finds no interpreter because it carries its own.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
outdir="${1:-$here/dist}"
version=$("$here/packaging/version.sh")
name="fettle-$version-linux-x86_64"

[ -x "$outdir/fettle" ] || {
    echo "binary/archive.sh: no binary at $outdir/fettle — run binary/build.sh first" >&2
    exit 1
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 755 "$work"
stage="$work/$name"
mkdir -p "$stage"

install -m 755 "$outdir/fettle" "$stage/fettle"
cp "$here/fettle.toml.example" "$here/README.md" "$here/LICENSE" "$stage/"
cp "$here/contrib/fettle.bash" "$stage/fettle.bash"

# Consume the requirement measured from every bundled ELF object during build.
# A historical fixed floor lied after the build host's Python extensions changed.
glibc_min=$(cat "$outdir/fettle-glibc-min.txt" 2>/dev/null || true)
printf '%s\n' "$glibc_min" | grep -qE '^[0-9]+(\.[0-9]+)+$' || {
    echo 'binary/archive.sh: missing/invalid measured glibc floor; rebuild with binary/build.sh' >&2
    exit 1
}
cp "$outdir/fettle-glibc-min.txt" "$stage/glibc-min.txt"
cat > "$stage/RUNNING.md" <<EOF
# fettle $version — prebuilt x86_64 binary

A single self-contained executable. No python needed, nothing to install.

    ./fettle --version
    ./fettle -H --dry-run           # system hardening audit, changes nothing

\`fettle --version\` prints \`$version (binary)\` so a bug report says which artifact
it came from.

## It needs glibc $glibc_min or newer

This requirement is measured from the symbol requirements of the executable and
its bundled shared libraries, including Python extension modules. Check the target's
version with \`ldd --version\`. This is a necessary compatibility requirement;
the tested target list is recorded in the repository's maintenance verification.

If the target is older, use the distro package or the zipapp with Python 3.11+.
Changing the build host or interpreter can change this floor. A build-host smoke
pass alone does not prove that the binary runs on an older distribution.

## Putting it on PATH

    sudo install -m 755 fettle /usr/local/bin/fettle

## Bash completion

    source ./fettle.bash

## Configuration

\`fettle.toml.example\` is a commented example. Copy it to
\`~/.config/fettle/config.toml\` and edit; fettle runs fine without one.

See README.md for what the tool actually does, and
https://github.com/pasadoorian/fettle/wiki for the full manual.
EOF

mkdir -p "$outdir"
tar -czf "$outdir/$name.tar.gz" -C "$work" "$name"
( cd "$work" && zip -qr "$outdir/$name.zip" "$name" )

ls "$outdir/$name.tar.gz" "$outdir/$name.zip"
