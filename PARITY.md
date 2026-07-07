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
| aur-audit (`-A`) | ✅ (restored) | Reproduces update.sh's health/metrics table (AGE, VOTES, OOD, ORPHAN, RECENTLY-CHANGED) + not-found list + maintainer-change section → `~/aur-audit.txt`. Provenance/health only. |
| aur-ioc-scan (`-S`, renamed from aur-scan) | ✅ (mostly) | Scans installed AUR packages for IoCs: known-bad package names + malicious maintainer accounts + malicious JS-cache traces → `~/aur-ioc-scan.txt`. See the two deliberate omissions below. |

## Intentional differences (⚠️ — documented, no action)

- **`-A`/`-S` unify into `pkg-audit`.** In bash they were distinct; the port routes
  both through the normalized `Finding` model (PLAN §3.8). `fettle -A` and `-S` are
  distinct commands again (M6.1): `-A` is the health table, `-S` is the IoC scan.
- **`pkg-audit` is the cross-distro umbrella.** update.sh had no equivalent; fettle
  keeps a normalized-`Finding` `pkg-audit` (PLAN §3.8) that the Debian/Flatpak/Snap
  backends will feed. On Arch it overlaps `-A`/`-S` in coverage but not presentation.
- **jq removed.** All AUR JSON parsing is stdlib Python now (PLAN §3.6, the jq-killer).
- **Lazy root elevation.** update.sh unconditionally `exec sudo`s at startup; fettle
  elevates only when a selected action mutates the system, so `-A`/`-S`/`-p` run
  unprivileged (PLAN §3.4). Reports are written directly as the user.
- **Host-persistence indicators deferred.** The old `-S` bpf-hidden-map / sudo-shim /
  systemd-`Restart=always` checks move to **System Supply Chain (`sys-audit`)**,
  built in Phase 2 (M9–M11). They exist nowhere yet — a known coverage gap until then.

## Deliberate omissions from `-S` (chosen, not accidental)

`aur-ioc-scan` was scoped to *installed-package* indicators to keep it simple and
avoid disturbing later phases. Two `update.sh` `aur_scan` blocks are intentionally
not carried over:

1. **Cached-PKGBUILD / `.install` risky-build-logic scan** (grep `~/.cache/{yay,paru,
   pamac}` for `npm install`, `curl…|sh`, etc.) — covered **at install time** by the
   yay hook + `fettle aur-precheck` (M5); the post-hoc cache sweep is dropped.
2. **Host-persistence indicators** — deferred to `sys-audit` (see above).

Everything else from `aur_audit` (-A) and the package/account/npm IoC checks of
`aur_scan` (-S) is reproduced, including the `-A` `VOTES`/`AGE(d)`/`RECENTLY-CHANGED`
columns (`aur_recent_days`, default 21) and the maintainer-change re-adoption tell.

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
