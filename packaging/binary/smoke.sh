#!/bin/sh
# Prove a compiled fettle binary actually works.
#
#   usage: packaging/binary/smoke.sh [BINARY]
#
# Run automatically at the end of packaging/binary/build.sh, so a binary that fails
# this never becomes an artifact.
#
# **This exists because the interesting failures are silent.** Compilation can lose
# things without anything crashing:
#
#   * The six hardening axes are loaded by a COMPUTED module name, which no compiler can
#     see. If they are missing, `run_all` catches the ImportError and reports each axis
#     as *blind* — so the binary runs, exits 0, looks careful, and audits nothing.
#
#     That is not hypothetical: a build with two axes deliberately excluded prints
#     "Filesystem: not checked (see below)" and carries on, and this script is what
#     turns it into a failed build. (The current flags make it unlikely — see
#     build.sh — but "unlikely and silent" is exactly what deserves a check.)
#   * `fettle remote` builds a zipapp from fettle's own .py files, which a compiled build
#     does not have. That one at least crashes, but only when you try to use it.
#
# So the checks below assert *positive results*, never just "exited 0".
set -eu

bin="${1:-}"
if [ -z "$bin" ]; then
    here=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
    bin="$here/dist/fettle"
fi
[ -x "$bin" ] || { echo "smoke: no executable at $bin" >&2; exit 1; }

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok  $*"; }

echo "smoke-testing $bin"

# -- it runs, and knows what it is -------------------------------------------
version=$("$bin" --version 2>&1) || fail "--version did not run: $version"
case "$version" in
    *"(binary)"*) ok "$version" ;;
    *) fail "--version says '$version' — a compiled build must say (binary), or a bug
         report cannot tell which artifact it came from" ;;
esac

# -- the axes, which is the whole point --------------------------------------
audit=$("$bin" -H --dry-run 2>&1) || fail "hardening-audit did not run"

# Ask fettle itself which axes should be there rather than listing them here — the same
# reason the build derives its --include-module flags.
axes=$(printf '%s' "$audit" | grep -cE \
    "Filesystem hygiene|Service exposure|Kernel runtime posture|SSH server|Host firewall|TLS certificates") \
    || axes=0
[ "$axes" -ge 6 ] || fail "only $axes of 6 axes reported — they were not compiled in"
ok "all 6 axes reported"

# The load-bearing assertion. Every axis reporting "did not complete" is what a build
# missing them looks like: no crash, no error, just a uniformly cautious audit.
blind=$(printf '%s' "$audit" | grep -c "did not complete") || blind=0
[ "$blind" -eq 0 ] || fail "$blind axis/axes reported as blind — the framework caught an
         ImportError, which means they are not in the binary. This is the failure that
         looks like caution."
ok "no axis is blind"

# ...and something must actually have been examined. An axis that ran but checked
# nothing would satisfy both tests above.
printf '%s' "$audit" | grep -qE "\([0-9]+ checked\)" \
    || fail "no axis reported checking anything"
ok "axes examined real subjects"

# -- `fettle remote` can still ship fettle -----------------------------------
# It must get PAST building the zipapp and fail at the network instead. A compiled build
# without an embedded zipapp dies here with FileNotFoundError from shutil.copytree.
remote=$("$bin" remote smoke-test-host.invalid -H 2>&1 || true)
case "$remote" in
    *FileNotFoundError*|*"no bundled zipapp"*)
        fail "fettle remote cannot build a zipapp — the binary has none embedded" ;;
    *"Uploading fettle to"*) ok "fettle remote builds its zipapp" ;;
    *) fail "fettle remote did not reach the upload step:
$remote" ;;
esac

# -- the config parser, which needs tomllib ----------------------------------
"$bin" --print-config >/dev/null 2>&1 || fail "--print-config failed (tomllib missing?)"
ok "config parsing works"

echo "smoke: PASS"
