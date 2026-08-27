#!/bin/sh
# Assemble a draft release: create it if absent, attach every staged file, and prove
# afterwards that they all arrived.
#
#   usage: publish.sh TAG TITLE NOTES_FILE STAGED_DIR [--prerelease]
#
# Replaces a single `gh release create … staged/*`, which failed three ways at once when
# one asset upload returned HTTP 400 during the v1.16.0 release:
#
#   1. **It aborted mid-upload.** The release object had been created and two of nine
#      assets attached. `gh` exits on the first upload error, so the remaining seven were
#      never attempted.
#   2. **It could not be re-run.** `gh release create` fails when the release already
#      exists, so re-running the failed job could only ever produce "already exists" —
#      the one recovery path a CI operator will actually try.
#   3. **Nothing checked the result.** The job failed loudly *that* time. Had the 400 hit
#      the last asset instead of the seventh, `gh` would have exited 0 with a release
#      missing a package, and the only signal would have been someone counting files on
#      the release page.
#
# The third is the one worth the script. A half-populated release is not a failed
# release: it installs, it runs, and the artifact somebody wanted is simply absent.
set -eu

tag="${1:?usage: publish.sh TAG TITLE NOTES_FILE STAGED_DIR [--prerelease]}"
title="${2:?missing TITLE}"
notes="${3:?missing NOTES_FILE}"
staged="${4:?missing STAGED_DIR}"
prerelease="${5:-}"

[ -f "$notes" ] || { echo "publish: no notes file at $notes" >&2; exit 1; }
[ -d "$staged" ] || { echo "publish: no staged directory at $staged" >&2; exit 1; }

set -- "$staged"/*
[ -e "$1" ] || { echo "publish: $staged is empty — nothing to attach" >&2; exit 1; }

# -- create, or adopt an existing draft --------------------------------------
# Idempotent on purpose: re-running this job after a flaky upload must repair the
# release, not refuse to touch it.
if gh release view "$tag" >/dev/null 2>&1; then
    echo "publish: $tag already exists — attaching to it (repair run)"
else
    flags="--draft --notes-file $notes --title $title"
    if [ "$prerelease" = "--prerelease" ]; then
        flags="$flags --prerelease"
    fi
    # Created with NO assets. Attaching them separately is what stops one bad upload
    # from taking the release object down with it.
    # shellcheck disable=SC2086
    gh release create "$tag" $flags
    echo "publish: created draft $tag"
fi

# -- attach every file, one at a time, with retries --------------------------
# One `gh release upload` per file so a failure is isolated to that file, and three
# attempts because the failure that prompted this was transient (HTTP 400 from the
# upload endpoint, same file succeeded on a later manual attempt).
failed=""
for path in "$@"; do
    name=$(basename "$path")
    attempt=1
    while :; do
        if gh release upload "$tag" "$path" --clobber; then
            echo "publish: attached $name"
            break
        fi
        if [ "$attempt" -ge 3 ]; then
            echo "publish: giving up on $name after 3 attempts" >&2
            failed="$failed $name"
            break
        fi
        echo "publish: upload of $name failed (attempt $attempt) — retrying" >&2
        attempt=$((attempt + 1))
        sleep $((attempt * 5))
    done
done

# -- prove they all arrived --------------------------------------------------
# The check that makes a silent partial release impossible. Asked of the release itself
# rather than inferred from the upload loop: an upload can report success and still
# leave nothing attached, and this is the last chance to notice before a human hits
# publish.
attached=$(gh release view "$tag" --json assets --jq '.assets[].name' | sort)
missing=""
for path in "$@"; do
    name=$(basename "$path")
    printf '%s\n' "$attached" | grep -qxF "$name" || missing="$missing $name"
done

if [ -n "$missing" ]; then
    cat >&2 <<EOF
publish: the release is INCOMPLETE.

  missing:$missing

Nothing has been published — the release is still a draft. Re-run this job to retry the
missing assets; it will attach to the existing draft rather than fail.
EOF
    exit 1
fi

echo "publish: $tag has all $# staged asset(s) attached"
[ -z "$failed" ] || { echo "publish: (but uploads reported failures:$failed)" >&2; exit 1; }
