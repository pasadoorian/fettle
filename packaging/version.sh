#!/bin/sh
# Print fettle's version, read from pyproject.toml.
#
# One source of truth for all three packagers and, later, for the release workflow's
# guard that the git tag and the packaged version agree. A release tagged v1.0.0 whose
# packages call themselves 0.120.0 installs, runs, and lies about what it is — so every
# bug report afterwards names the wrong version.
#
# Plain sed rather than python or a toml parser: this runs first in build containers
# that may have neither, and the line it reads has been stable since the file was
# created. `^version` will not match `target-version` in the ruff section.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$here/pyproject.toml" | head -1)

if [ -z "$version" ]; then
    echo "packaging/version.sh: no version found in pyproject.toml" >&2
    exit 1
fi
echo "$version"
