# Arch cutover — parity sign-off (M6)

Behavioral comparison of `fettle` (Arch backend) against the frozen
`linux_hacks/update.sh` it replaces. Verdicts: ✅ parity · ⚠️ intentional
difference (per the design plan) · ❌ was an accidental gap, now fixed.

Test suite green (90 passing); `fettle --all --dry-run` reproduces update.sh's
default run on Manjaro (7 steps: clean, orphans, update, rebuilds, python-rebuild,
config-drift, firmware).

## Per-action status

| Action | Verdict | Notes |
|---|---|---|
| clean (`-c`) | ✅ | Same commands; only a trivial `rm` ordering diff. |
| orphans/foreign (`-o`) | ✅ (fixed) | `alien-pkgs.txt` now written from `pacman -Qm` (name **and** version), filtered on the name — was regressed to `-Qmq` (names only). Orphan prompt/removal identical. |
| update (`-u`) | ✅ | Identical mirror refresh (`pacman-mirrors -f`), pamac-all-in-one branch, `pacman -Syuu`, and `yay -Sua …` invocation. One bash function split into `update_system`+`update_extras`; command order byte-equivalent. |
| rebuilds (`-r`) | ✅ | Adds a graceful `checkrebuild`-absent skip. Minor: doesn't re-print the name list before the confirm prompt (cosmetic). |
| python-rebuild (`-y`) | ✅ (fixed) | Logic at parity; **restored to the default/`--all` set** (was accidentally dropped from `DEFAULT_ACTIONS`). |
| config-drift/pacnew (`-p`) | ✅ | Identical `pacdiff -o`; section retitled "Config file drift" (cross-distro naming). |
| firmware (`-f`) | ✅ | Shared `fwupdmgr` impl on the base class. Empty-detection uses a stdout string heuristic instead of exit code — converges in practice. |
| kernels (`-k`) | ✅ (fixed) | Restored the `mhwd-kernel -l` available-kernel listing and ported the exact running-kernel guard (`uname -r` → major.minor digits, compared exactly — the old code did a buggy substring match). Excluded from `--all`, as in bash. |
| aur-audit (`-A`) / aur-scan (`-S`) | ⚠️ | Both converge on the normalized `pkg-audit` (PLAN §3.6a/§3.8). See intentional differences below. |

## Intentional differences (⚠️ — documented, no action)

- **`-A`/`-S` unify into `pkg-audit`.** In bash they were distinct; the port routes
  both through the normalized `Finding` model (PLAN §3.8). `fettle -A` and `-S` are
  now aliases and produce the same report.
- **Report path** `~/aur-audit.txt` → `~/pkg-audit.txt` (PLAN §3.8 convergence).
- **jq removed.** The tabular metrics report becomes one severity-tagged
  `Finding` line per issue (PLAN §3.6, the jq-killer).
- **Lazy root elevation.** update.sh unconditionally `exec sudo`s at startup; fettle
  elevates only when a selected action mutates the system, so `-A`/`-S`/`-p` run
  unprivileged (PLAN §3.4). Reports are written directly as the user.
- **Host-persistence indicators deferred.** The old `-S` bpf-hidden-map / sudo-shim /
  systemd-`Restart=always` checks move to **System Supply Chain (`sys-audit`)**,
  built in Phase 2 (M9–M11). They exist nowhere yet — a known coverage gap until then.

## Known deferred gaps (⚠️ — decide before/at cutover)

These are the only non-cosmetic behaviors from update.sh not currently reproduced.
None block the everyday update/maintenance path; all concern the audit surface.

1. **Cached-PKGBUILD / `.install` risky-build-logic scan** (old `aur_scan` block 3:
   grep `~/.cache/{yay,paru,pamac}` PKGBUILDs for `npm install`, `curl…|sh`, etc.).
   This is now performed **at install time** by the yay hook + `fettle aur-precheck`
   (M5), but the *post-hoc* scan over already-cached build files is not ported into
   `pkg-audit`. Decision: accept install-time coverage as sufficient, or re-add a
   post-hoc scanner to `AURSource`.
2. **`-A` informational columns dropped:** `VOTES`/`NumVotes`, the `AGE(d)` column,
   and the `RECENTLY-CHANGED` (≤ `AUR_RECENT_DAYS`, 21d) eyeball signal have no
   equivalent — the `Finding` model reports only *problems*, and staleness is now the
   opposite test (> `aur_max_age_days`, 365d). The re-adoption *maintainer-change*
   diff is preserved; the recent-change *tell* is not.

## Remaining cutover steps (deploy — done by the operator, post-testing)

The strangler plan (PLAN §5) keeps `update.sh` **deployed and frozen** in
`linux_hacks` until real-world testing confirms parity. When ready:

1. **Install the launcher** (no pip needed — fettle is pure-stdlib):
   `ln -s ~/src/fettle/bin/fettle ~/.local/bin/fettle`
   (or drop it in for the old updater: `ln -sf ~/src/fettle/bin/fettle ~/update.sh`).
2. **Deploy the yay hook:** `cp ~/src/fettle/contrib/yay-init.lua ~/.config/yay/init.lua`.
3. **Archive the bash originals** in `linux_hacks` (`update.sh`, `aur-precheck.sh`,
   `lib/aur-common.sh`) with a pointer to this repo. `lib/output.sh` stays there for
   the other bash scripts. *(Left untouched by fettle — `linux_hacks` is read-only.)*
