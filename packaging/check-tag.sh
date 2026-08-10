#!/bin/sh
# Check that a release tag matches the version in pyproject.toml.
#
#   usage: packaging/check-tag.sh v1.0.0
#
# The first thing the release workflow runs, and the reason it exists: a release tagged
# v1.0.0 whose packages call themselves 0.120.0 installs, runs, and lies about what it
# is — so every bug report afterwards names the wrong version, and the artifacts on the
# release page disagree with the artifacts on disk. That is worse than a failed build,
# because a failed build is obvious.
#
# It is a script rather than a few lines of YAML so the suite can test it
# (tests/test_packaging.py) and so it can be run by hand before tagging:
#
#   packaging/check-tag.sh "v$(packaging/version.sh)"   # always passes, by construction
#
# Prints the bare version on success. Exits 1 with an explanation on mismatch.
set -eu

tag="${1:?usage: check-tag.sh TAG}"
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

case "$tag" in
    v*) ;;
    *)  echo "check-tag: '$tag' does not start with 'v' — release tags look like v1.0.0" >&2
        exit 1 ;;
esac

tag_version=${tag#v}
file_version=$("$here/packaging/version.sh")

if [ "$tag_version" != "$file_version" ]; then
    cat >&2 <<EOF
check-tag: the tag and pyproject.toml disagree.

  tag            $tag        (version $tag_version)
  pyproject.toml $file_version

Bump the version in pyproject.toml and fettle/__init__.py to $tag_version, or delete
and re-push the tag as v$file_version. Whichever is right, they have to match before
anything is built — a package that names the wrong version is worse than no package.
EOF
    exit 1
fi

echo "$tag_version"
