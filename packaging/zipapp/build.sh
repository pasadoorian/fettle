#!/bin/sh
# Build the zipapp and its archives into $OUTDIR (default: dist/).
#
#   usage: packaging/zipapp/build.sh [OUTDIR]
#
#   dist/fettle.pyz                          the zipapp on its own
#   dist/fettle-<version>-zipapp.tar.gz      self-contained archive
#   dist/fettle-<version>-zipapp.zip         same, for people who prefer zip
#
# This is the artifact that runs EVERYWHERE — any distro, any architecture, as long as
# there is a python 3.11+. The Nuitka binary that comes later is built on one glibc and
# therefore does not; this is what covers the machines it misses.
#
# The `-zipapp` in the name matters: GitHub attaches its own "Source code (zip)" and
# "(tar.gz)" to every tag, named fettle-<version>.zip and .tar.gz. Without the suffix
# these would collide with those on the release page.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
outdir="${1:-$here/dist}"
version=$("$here/packaging/version.sh")

mkdir -p "$outdir"

# Built by fettle's own remote.build_zipapp — the same function `fettle remote` uses to
# ship itself to a host. One builder, so the artifact people download and the one that
# lands on a remote machine cannot become different things.
( cd "$here" && python3 -c "
import sys
from pathlib import Path
sys.path.insert(0, '.')
from fettle.remote import build_zipapp
build_zipapp(Path(sys.argv[1]))
" "$outdir/fettle.pyz" )

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 755 "$work"
stage="$work/fettle-$version"
mkdir -p "$stage"

cp "$outdir/fettle.pyz" "$stage/"
cp "$here/fettle.toml.example" "$here/README.md" "$here/LICENSE" "$stage/"
cp "$here/contrib/fettle.bash" "$stage/fettle.bash"

# Same launcher as the distro packages, from the same template — see
# packaging/wrapper.sh.in. Here it resolves the zipapp beside itself rather than a
# PYTHONPATH, so the unpacked directory works wherever it is put.
sed -e 's|@SETUP@|here=$(CDPATH= cd -- "$(dirname -- "$0")" \&\& pwd)|' \
    -e 's|@TARGET@|"$here/fettle.pyz"|' \
    "$here/packaging/wrapper.sh.in" > "$stage/fettle"
chmod 755 "$stage/fettle"

cat > "$stage/RUNNING.md" <<EOF
# fettle $version — zipapp

Runs on any Linux with **python 3.11 or newer**. Nothing to install and no
dependencies; the whole tool is the single \`fettle.pyz\` file.

    ./fettle --version              # the launcher finds a suitable python for you
    ./fettle -H --dry-run           # system hardening audit, changes nothing

\`./fettle\` is a small shell script that picks a suitable interpreter. Use it rather
than running \`python3 fettle.pyz\` yourself: on RHEL/Rocky/Alma 9 and Ubuntu 22.04 the
system \`python3\` is older than 3.11, and fettle is neither built nor tested for those.
It will not necessarily fail at once — it may get some way in and then stop on whatever
3.11 feature it reaches first — which is worse than refusing. The launcher looks for
\`python3.11\` and friends before falling back, so it picks a supported one.

## Putting it on PATH

    sudo cp fettle.pyz /usr/local/lib/fettle.pyz
    sudo cp fettle     /usr/local/bin/fettle     # edit the path inside it first

Or just run it from where it is.

## Bash completion

    source ./fettle.bash

## Configuration

\`fettle.toml.example\` is a commented example. Copy it to
\`~/.config/fettle/config.toml\` and edit; fettle runs fine without one.

See README.md for what the tool actually does.
EOF

tar -czf "$outdir/fettle-$version-zipapp.tar.gz" -C "$work" "fettle-$version"
( cd "$work" && zip -qr "$outdir/fettle-$version-zipapp.zip" "fettle-$version" )

ls "$outdir/fettle.pyz" "$outdir/fettle-$version-zipapp.tar.gz" \
   "$outdir/fettle-$version-zipapp.zip"
