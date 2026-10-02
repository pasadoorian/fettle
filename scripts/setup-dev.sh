#!/bin/sh
# Create an isolated environment using the reviewed dependency constraints.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$here"
python="${FETTLE_PYTHON:-python3}"
envdir="${FETTLE_DEV_ENV:-venv-fettle-dev}"
extras=dev
if [ "${1:-}" = "--web" ]; then extras=dev,web; fi
"$python" -m venv "$envdir"
"$envdir/bin/python" -m pip install -c constraints/build.txt --upgrade pip
"$envdir/bin/python" -m pip install --build-constraint constraints/build.txt \
    -c constraints/dev.txt -c constraints/web.txt -e ".[${extras}]"
