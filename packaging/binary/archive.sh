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

# The glibc floor is MEASURED, not inferred from the build host's version. The outer
# binary only needs GLIBC_2.34, but the libpython Nuitka bundles needs 2.38 — so the
# floor comes from the interpreter that was compiled in, not from the compiler. Verified
# by running this binary on eight distros; the four that fail and the four that work are
# both listed, because "needs glibc 2.38" is not a sentence most people can act on.
cat > "$stage/RUNNING.md" <<EOF
# fettle $version — prebuilt x86_64 binary

A single self-contained executable. No python needed, nothing to install.

    ./fettle --version
    ./fettle -H --dry-run           # system hardening audit, changes nothing

\`fettle --version\` prints \`$version (binary)\` so a bug report says which artifact
it came from.

## It needs glibc 2.38 or newer

Verified by running it:

| works | does not work |
|---|---|
| Ubuntu 24.04 (2.39) | Ubuntu 22.04 (2.35) |
| Debian 13 (2.41) | Debian 12 (2.36) |
| Fedora 40+ (2.40) | RHEL / Rocky / AlmaLinux 9 (2.34) |
| Arch, Manjaro (2.44) | |

On the systems in the right-hand column, use the distro package or the zipapp — both
work everywhere and are on the same release page. The limit comes from the python
runtime compiled into this binary, not from fettle.

## Putting it on PATH

    sudo install -m 755 fettle /usr/local/bin/fettle

## Bash completion

    source ./fettle.bash

## Configuration

\`fettle.toml.example\` is a commented example. Copy it to
\`~/.config/fettle/config.toml\` and edit; fettle runs fine without one.

See README.md for what the tool actually does.
EOF

mkdir -p "$outdir"
tar -czf "$outdir/$name.tar.gz" -C "$work" "$name"
( cd "$work" && zip -qr "$outdir/$name.zip" "$name" )

ls "$outdir/$name.tar.gz" "$outdir/$name.zip"
