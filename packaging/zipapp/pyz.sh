#!/bin/sh
# Build just the zipapp, to a named file.
#
#   usage: packaging/zipapp/pyz.sh OUTFILE
#
# Split out of zipapp/build.sh because the compiled binary needs one too — it bundles a
# prebuilt zipapp so `fettle remote` keeps working (see packaging/binary/build.sh) — and
# the binary build should not have to pull in `zip` just to reach the same few lines.
#
# Built by fettle's own remote.build_zipapp, the same function `fettle remote` uses, so
# the file people download, the one embedded in the binary, and the one that lands on a
# remote host are all the same thing.
set -eu

out="${1:?usage: pyz.sh OUTFILE}"
here=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

mkdir -p "$(dirname -- "$out")"
( cd "$here" && python3 -c "
import sys
from pathlib import Path
sys.path.insert(0, '.')
from fettle.remote import build_zipapp
build_zipapp(Path(sys.argv[1]))
" "$out" )
