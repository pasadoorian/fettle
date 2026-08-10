#!/bin/sh
# Compile fettle to a single x86_64 binary with Nuitka.
#
#   usage: packaging/binary/build.sh [OUTDIR] [PYTHON]
#
# Nuitka translates the python to C and compiles it, so the result is a real native
# binary rather than an interpreter with an archive glued to it. That matters here more
# than usual: bash completion invokes fettle on every tab press.
#
# THE AXES MUST BE LISTED EXPLICITLY. fettle loads them with
# `import_module(f".{name}", __package__)` — a computed name no compiler can see. If they
# are missing the binary does not crash: the axis framework catches the import error and
# reports each one as *blind*, so a broken build looks like a cautious one. The smoke
# test below is what actually proves they are there.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
outdir="${1:-$here/dist}"
python="${2:-$here/venv-nuitka-build/bin/python}"
version=$("$here/packaging/version.sh")

if [ ! -x "$python" ]; then
    echo "binary/build.sh: no python at $python" >&2
    echo "  python -m venv ./venv-nuitka-build && ./venv-nuitka-build/bin/pip install nuitka" >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$outdir"

# The hardening axes, named explicitly because they are loaded by a COMPUTED module name
# that static analysis cannot see.
#
# MEASURED, and not what I first wrote: `--include-package=fettle` below already pulls
# them in, so these flags are redundant. A build made without them was compiled and
# smoke-tested, and all six axes were present. They are kept as belt-and-braces for the
# one thing here that fails *silently* — see smoke.sh — but they are not what makes it
# work, and a comment claiming otherwise would send the next person down a false trail.
#
# Derived from AXIS_NAMES rather than listed, so a seventh axis cannot be forgotten.
axes=$(cd "$here" && python3 -c "
import sys
sys.path.insert(0, '.')
from fettle.hardening.axes import AXIS_NAMES
print(' '.join(AXIS_NAMES))
")
[ -n "$axes" ] || { echo "binary/build.sh: could not read AXIS_NAMES" >&2; exit 1; }
includes=""
for axis in $axes; do
    includes="$includes --include-module=fettle.hardening.axes.$axis"
done

# fettle/__main__.py cannot be the entry point: it does `from .cli import main`, a
# RELATIVE import that only resolves with the package as context, and the binary would
# compile happily then die at startup with "attempted relative import with no known
# parent package". `--python-flag=-m` is Nuitka's answer to that and brings its own
# semantics to argue with, so this generates a two-line entry point that imports
# absolutely — the same thing remote.build_zipapp already does for the zipapp, which
# makes the two artifacts start the same way.
# `fettle remote` builds a zipapp by copying fettle's own .py files off disk, and a
# compiled build has none — it fails with a bare FileNotFoundError traceback. So one is
# built here and embedded as a data file; remote.build_zipapp copies it out instead.
# About 800 KB on a 12 MB binary.
sh "$here/packaging/zipapp/pyz.sh" "$work/fettle.pyz"

cat > "$work/fettle-main.py" <<'ENTRY'
import sys

# Force UTF-8 on the output streams before anything prints.
#
# A normal CPython coerces the C locale to UTF-8 (PEP 538/540), so on a machine with no
# LANG set — a container, a cron job, a minimal server — `sys.stdout.encoding` is still
# utf-8. The interpreter Nuitka bundles does NOT do that coercion: it reports ascii, and
# fettle dies on its very first section header with
#
#   UnicodeEncodeError: 'ascii' codec can't encode character '\u25b8'
#
# which is `▸`. Measured in a bare debian:13 container, where the zipapp printed fine
# under the system python and the binary crashed. Forcing it here makes the binary match
# every other artifact rather than inventing a policy.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import fettle.cli

sys.exit(fettle.cli.main())
ENTRY

# shellcheck disable=SC2086
( cd "$here" && "$python" -m nuitka \
    --onefile \
    --output-dir="$work" \
    --output-filename=fettle \
    --company-name=fettle --product-name=fettle --product-version="$version" \
    --assume-yes-for-downloads \
    --quiet \
    $includes \
    --include-package=fettle \
    --include-data-files="$work/fettle.pyz=fettle/fettle.pyz" \
    "$work/fettle-main.py" )

install -m 755 "$work/fettle" "$outdir/fettle"

# A binary that fails the smoke test never becomes an artifact. The failures that matter
# here are silent — a build missing the axes runs, exits 0, and audits nothing — so this
# is not optional polish.
sh "$here/packaging/binary/smoke.sh" "$outdir/fettle"

echo "$outdir/fettle"
