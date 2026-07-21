# Changelog

All notable changes to fettle are recorded here. Newest first.

## [Unreleased]

## [0.12.0] — machine-readable JSON output; HTML report (beta)

- **Every report and run-log now has a structured `.json` sibling.** Alongside the
  `.txt`, fettle writes `<name>-<ts>.json` under `~/.fettle/{reports,logs}/<host>/`
  — a `{schema, tool, host, timestamp, fettle_version, data}` envelope whose `data`
  is the real structure the report was built from (scored hardening packages,
  supply-chain findings with severity, the upgrade-check result, package lists, log
  transcript + argv/exit). Same `0600`, same rotation (txt+json rotate as a unit).
  Toggle with `[reports] json = false`.
- **`fettle report` — an HTML dashboard (BETA, initial revision).** Regenerates a
  single self-contained `~/.fettle/report.html` (`0600`) from all stored JSON,
  across every host: a per-host summary card row (latest hardening band tally,
  per-type counts, latest run), collapsible sections grouped by report type with
  native rendering (scored hardening tables, severity-coloured findings, upgrade
  verdicts, package lists, log transcripts), and a host/type/text filter. Pure
  stdlib, no external assets. `fettle report --open` opens it in a browser.
  *This is a first cut — the layout and contents will evolve; feedback welcome.*
- **`fettle report --backfill-json`** — one-off converter that gives pre-0.12
  `.txt` reports/logs a JSON sibling (idempotent, non-destructive) so the dashboard
  is populated without re-scanning.
- Remote report fetch-back now pulls the `.json` siblings too.

## [0.11.0] — reports moved to ~/.fettle, timestamped & rotated; run logs

- **Reports no longer clutter `$HOME`.** Every report (`aur-audit`, `pkg-audit`,
  `aur-ioc-scan`, `hardening-audit`, `upgrade-check`, the orphans list) now lands
  under **`~/.fettle/reports/<host>/`**, **timestamped** (so runs don't clobber
  each other), **`chmod 0600`** (they name your packages and can hold system
  detail), and **rotated** to the newest `keep` (default 5) *per host, per report
  type*. `<host>` is `local` locally, or the target hostname for `fettle remote
  <host> …`, so each machine keeps its own history. Pre-0.11 `~/*.txt` reports are
  left untouched; fettle notes the move once.
- **Every run is recorded to a transcript** under `~/.fettle/logs/<host>/run-<ts>.txt`
  (same `0600` + rotation). On an interactive terminal fettle captures the whole
  session — its own output **and** every tool it runs — `script(1)`-style, by
  re-execing once under a pseudo-terminal so the run happens on a real tty and
  colours / `sudo` / PKGBUILD prompts are unaffected. Logs are ANSI-stripped;
  non-interactive runs record fettle's own output only.
- **New `[reports]` config:** `keep` (retention per host+type, default 5), `dir`
  (base-dir override, default `~/.fettle`), `log` (set `false` to disable the
  run-log).

## [0.10.0] — scored, ranked hardening audit

- **`hardening-audit` output is now scored and ranked.** Each binary gets a risk
  score — `Σ weight(missing protection) × 3 when it's a privilege boundary
  (setuid/setgid or a configured `sensitive_packages`) — mapped to **Critical /
  High / Medium / Low** bands, and packages are sorted worst-first by their most
  vulnerable binary. So the outlier that matters (e.g. a setuid helper missing a
  stack canary) rises to the top instead of drowning under big, harmless packages.
- **Focused terminal, full detail on disk.** The on-screen table shows only the
  **Critical** and **High** packages (`BAND · SCORE · P · PACKAGE · BINS ·
  MISSING`), collapses Medium/Low into a one-line tally, and writes the complete
  per-criterion **matrix** (a column per protection) to `~/hardening-audit.txt`.
  The summary still reports every band's count.
- **New `[hardening]` scoring keys** (all optional): `sensitive_packages` (globs
  — mark network daemons as privilege boundaries; setuid/setgid is automatic),
  `priv_multiplier`, and `weights` (per-criterion). Band thresholds are calibrated
  constants.

## [0.9.0] — binary hardening audit

- **New `hardening-audit` check (`-H` / `--hardening-audit`).** Runs `checksec`
  over your installed executables and flags packages whose binaries were **not**
  built with the hardening the distro says it uses — an upstream Makefile
  clobbering `CFLAGS`, a vendored prebuilt binary, or a sloppy AUR build. It's a
  supply-chain question, not a generic lint. Read-only, rootless, cross-distro,
  and **opt-in** (not in the default `-a` set). Findings roll up per package and
  save to `~/hardening-audit.txt`.
  - The baseline is **derived from the distro's own build policy** — Arch's
    `makepkg.conf` *plus* GCC's compiled-in `--enable-default-pie/ssp` (where PIE
    and the stack canary actually come from), or Debian's `dpkg-buildflags` — so
    a deviation means the package genuinely departed from how everything else was
    built.
  - Four always-on accuracy corrections keep it honest: non-ELF files are skipped
    (checksec otherwise "fails" every check on a script), static Go/Rust binaries
    are skipped, `_FORTIFY_SOURCE=No` is ignored when nothing was fortifiable, and
    `stack_clash` is never treated as pass/fail. Detectable vs. not is documented
    in the README.
  - Prune the (deliberately long) default list with `[hardening]`
    `exclude_checks` / `exclude_packages` / `exclude_paths` globs in your config;
    fettle reports how many findings your exclude lists hid. Needs `checksec`
    (skipped with a note if absent).

## [0.8.0] — auto-updates posture check

- **New `auto-updates` check (`-x` / `--auto-updates`).** A read-only,
  informational report of whether the system is configured to update itself
  unattended. Runs by default in `-a`; needs no root; cross-distro.
  - **Debian/Ubuntu:** reads `apt-config dump` (the authoritative
    `APT::Periodic::Unattended-Upgrade` / `Update-Package-Lists` values, honoring
    the full `apt.conf.d/` layering), whether `unattended-upgrades` is installed,
    and `systemctl is-enabled apt-daily-upgrade.timer`.
  - **Arch/Manjaro:** checks a curated list of known community auto-updater
    systemd timers (`arch-update.timer`, `pacman-auto-update.timer`,
    `yay-auto-update.timer`, `topgrade.timer`, …) via `systemctl is-enabled`;
    none enabled = "manual updates — the Arch default". A custom-named timer
    isn't recognized (the tradeoff of name-matching).
  - It only reports the fact and offers no opinion either way.

## [0.7.0] — AUR pre-upgrade IoC gate

- **Flagged AUR packages are caught *before* they're built.** Before `yay -Sua`,
  `fettle -u` / `-a` now pre-checks the AUR packages it's about to upgrade against
  the IoC feeds (known-compromise names, malicious maintainers, orphan/out-of-date/
  stale) and **prompts to continue or abort** on any finding (default abort). A
  clean set just prints a one-line "no indicators". Previously the only AUR
  security check ran *after* the update.
- Applies to **`fettle remote <host> -u/-a`** too (same code runs on the host; the
  prompt comes over `ssh -t`). Under `--yes`, a **CRITICAL** finding aborts
  unattended unless you pass `--force-aur`. `--no-aur-precheck` (or
  `aur_precheck_on_update = false`) disables the gate.
- Covers the `yay -Qua` upgrade set; `--devel`/`-git` rebuilds that don't bump a
  version stay covered by the yay hook and the post-update `aur-ioc-scan`.

## [0.6.0] — clearer output; security audits in the default run

- **External-tool output is now framed.** When fettle hands off to yay/pacman/apt,
  it brackets that tool's live output in a labeled banner (`──── yay ──── output
  below is yay's, not fettle's ────`) so fettle's own messages are never mistaken
  for the package manager's. No capture, so PKGBUILD-review and sudo prompts still
  work.
- **`fettle` / `-a` now runs the security audits too.** The default set gained
  `pkg-audit` and `aur-ioc-scan` (appended, read-only), so a full run also reports
  package provenance and checks installed AUR packages against known-compromise
  feeds. Previously neither ran under `-a`.
- **Quieter cross-distro default runs.** A "skipping <action>" note now only prints
  for actions you *named* — default-set actions a distro can't do (e.g.
  `aur-ioc-scan` on Debian) are skipped silently.
- The bundled yay hook (`~/.config/yay/init.lua`) now prefers `fettle aur-precheck`
  over the legacy `aur-precheck.sh` when fettle is on `PATH`.

## [0.5.0] — remote AI upgrade-check

- **`fettle remote HOST upgrade-check`** — the experimental AI pre-upgrade advisor
  now works against a remote host. fettle collects a redacted snapshot **on the
  host** (read-only, no sudo, no API key) and runs the Claude analysis **on your
  machine** with your local key. Your key never leaves your machine, only your
  machine needs internet to Anthropic, and the report is saved locally as
  `~/upgrade-check-<host>.txt`. (Replaces the old behaviour, which ran the whole
  thing on the remote and wanted your key set there.) Missing `inxi` on the host
  degrades gracefully; on Debian the pending list reflects the host's cached apt
  data (Arch uses a fresh rootless sync).

## [0.4.5] — correctness & safety review fixes

_All items below were flagged and fixed during a Claude Fable 5 review of the
whole codebase._

- **User config is honoured on elevated runs.** `--config` is now carried across
  the `sudo` re-exec. Previously `sudo` reset `HOME=/root`, so system-changing
  runs re-resolved the config path to `/root`'s (usually absent) and silently used
  built-in defaults — ignoring your `keep_orphans`, `exclude_foreign`, and
  `[updaters]` exactly when they matter (e.g. orphan removal).
- **A missing external tool no longer crashes the run.** `command.run` returns a
  clean non-zero result instead of raising `FileNotFoundError`.
- **No spurious sudo prompt in read-only/dry-run queries.** `sudo -u <user>` is
  only used when actually running as root (it can't drop privileges you don't
  hold), so unprivileged queries like the `yay -Qua` preview run directly.
- **Vanilla Arch / EndeavourOS `update` no longer fails** on the Manjaro-only
  `pacman-mirrors` — it's now skipped when absent.
- **Root-owned cache/state no longer crashes a later user run.** The AUR IOC cache
  and maintainer snapshots degrade gracefully if unreadable, and are chowned back
  to the invoking user after a root run writes them.
- **Security: the remote zipapp** is uploaded to the remote user's `$HOME` under a
  random name (was a predictable world-writable `/tmp` path run under `sudo`).
- **`aur-precheck` never silently drops a package name** — everything after `--`
  is taken literally.

## [0.4.4] — Python rebuild check no longer flags Python itself

- **`-y` / `python-rebuild-check` ignores Python interpreter packages.** It used
  to list packages like `python312` (a separate, deliberately-installed Python
  interpreter) as "needing rebuild" just because they own `/usr/lib/python3.12`.
  Now the interpreter that owns an old Python dir is excluded (via its stdlib
  owner + a name-pattern fallback), so only genuinely **stranded modules** are
  flagged. Old Python dirs owned by *no* package are reported separately as
  removable leftover cruft, and skipped interpreters are named for transparency.

## [0.4.3] — kernel-removal safety fix

- **Debian/Ubuntu: never offer to remove the *newest* kernel.** Kernel management
  protected only the *running* kernel, so after a kernel upgrade before reboot
  (running the old kernel, newer one installed) it offered to purge the newer,
  next-boot kernel — a potential rollback. It now protects the running kernel
  **and** the newest installed one(s), compared numerically (a string sort ranks
  `6.8.0-99` above `6.8.0-124`), and nudges you to reboot when a newer kernel is
  installed but not yet active. Arch/Manjaro was audited and is unaffected
  (removal is user-named; the running series is refused).

## [0.4.2] — fixes

- **`fettle upgrade` now works** as a synonym for `update` (install package
  upgrades). The `--upgrade` flag already worked; the bare word didn't.

## [0.4.1] — fixes

- **Fixed the post-update AUR hint.** The Arch update summary pointed at
  `fettle -A -S`, a pre-v0.4.0 combo — since `-S` is now sys-audit, running it
  errored. It now correctly suggests `fettle -A -I` (AUR audit + IoC scan).
- **Clearer error for clashing shortcuts.** Combining a dispatch shortcut with an
  action flag (e.g. `fettle -A -S`) now prints a clear message instead of a
  cryptic sub-parser error; sub-options like `-S --list` still pass through.
- **`fettle sys-audit` with no arguments runs all checks** (was a "nothing to
  check" no-op) — matching `fettle -S`. Named categories and `--list` unchanged;
  the `remote` form still requires explicit categories/`--all`.
- **Debian/Ubuntu: autoremove previews first.** `apt-get autoremove` now lists the
  exact packages it would drop **before** asking, instead of confirming blind.

## [0.4.0] — CLI rework (breaking)

A **hard break** that reorganizes the command-line surface. Update any scripts,
aliases, or config files that used the old names.

**Switches — renamed / moved:**

| What | Old | New |
|---|---|---|
| config-file drift | `-p` / `--pacnew` | `-d` / `--config-drift` |
| AUR IoC scan | `-S` / `--aur-ioc-scan` | `-I` / `--aur-ioc-scan` |
| rebuild check | `--rebuilds` | `-r` / `--rebuild-check` |
| python rebuild check | `--python-rebuild` | `-y` / `--python-rebuild-check` |
| firmware check | `--firmware` (action `firmware`) | `-f` / `--firmware` (action `firmware-check`) |
| kernel | action `kernels` | `-k` / action `kernel` |
| package audit | `fettle pkg-audit` (word only) | `-P` / `--pkg-audit` (+ word) |
| upgrade | `-u` | `-u` / `--update` / `--upgrade` |

**New:**
- `-O` / `--only-update` — **safe metadata refresh + "what's upgradable" report**,
  no upgrade. Arch previews from a private cache (never `pacman -Sy`, so no
  partial-upgrade risk); Debian runs `apt update` + flatpak metadata.
- **Dispatch shortcuts** for the subcommand-style actions (subcommand forms stay
  for their options): `-S` → `sys-audit --all`, `-U` → `upgrade-check`, `-p` →
  `aur-precheck`.
- **`clean` now asks once** before deleting caches (`--yes` skips).
- **`aur-precheck` with no package** now scans *all* installed AUR packages (bare
  `fettle aur-precheck` / `-p` used to print nothing).

**`fettle remote` reworked** — `fettle remote [--ssh-arg X]... HOST <any
action/flags…>`. Everything after `HOST` is forwarded verbatim, so the whole CLI
works remotely. With no action named it still runs only the safe set
(`clean update firmware-check`), even under `--yes`.

**Config:**
- `default_actions` renamed to the new action names (`rebuild-check`,
  `python-rebuild-check`, `config-drift`, `firmware-check`). Old names are dropped
  with a warning pointing at the new spelling; hyphens and underscores both work.
- Removed the redundant `source_audit` action; `integrity` is now solely the
  `sys-audit` *packages* module.

**Removed:** old switches/long-options above no longer exist (they error rather
than silently doing something else).
