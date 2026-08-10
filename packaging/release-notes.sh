#!/bin/sh
# Print the release notes for a version, from CHANGELOG.md.
#
#   usage: packaging/release-notes.sh 1.0.0
#
# The changelog entry is already written for every release, by hand, with the reasoning
# in it. Writing a second set of notes on the release page would mean maintaining two
# accounts of the same change, and the one nobody reads is the one that goes stale.
#
# **Fails if there is no section for the version.** That is deliberate: the fallback
# would be GitHub's auto-generated commit list, which for a release like 1.0.0 is a wall
# of "packaging P4: …" lines and says nothing a user wants. A release with no notes
# should stop the build, not quietly ship.
set -eu

version="${1:?usage: release-notes.sh VERSION}"
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
changelog="$here/CHANGELOG.md"

# From `## [<version>]` up to the next `## [`. awk rather than sed because the range has
# to stop *before* the next heading, and the version contains dots that would need
# escaping in a regex — here it is compared as a literal string.
notes=$(awk -v want="## [$version]" '
    index($0, want) == 1 { grab = 1; print; next }
    grab && /^## \[/     { exit }
    grab                 { print }
' "$changelog")

if [ -z "$notes" ]; then
    echo "release-notes: CHANGELOG.md has no '## [$version]' section." >&2
    echo "Add one before tagging — the release page should say what changed, and the" >&2
    echo "auto-generated commit list is not that." >&2
    exit 1
fi

printf '%s\n' "$notes"

# A release page with six files and no explanation is unhelpful, and this part is the
# same every time, so it is generated rather than retyped.
cat <<'EOF'

---

## What to download

| file | for |
|---|---|
| `fettle_<version>_all.deb` | Debian, Ubuntu, and derivatives |
| `fettle-<version>-1.noarch.rpm` | RHEL, Rocky, AlmaLinux, Fedora |
| `fettle-<version>-1-any.pkg.tar.zst` | Arch, Manjaro, EndeavourOS |
| `fettle-<version>-zipapp.tar.gz` / `.zip` | anything else — runs on any Linux with python 3.11+ |
| `fettle.pyz` | the zipapp on its own, if you do not want the archive |

fettle is pure standard library: it needs **python 3.11 or newer** and nothing else.
On RHEL/Rocky/Alma 9 and Ubuntu 22.04 the system `python3` is older than that, so the
packages pull in a suitable interpreter and the launcher finds it for you.

## Verifying what you downloaded

```sh
sha256sum -c SHA256SUMS --ignore-missing
```
EOF
