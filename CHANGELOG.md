# Changelog

All notable changes to fettle are recorded here. Newest first.

## [Unreleased]

## [0.17.1] — advisory: warn-gate in the update flow (Phase 19 M1)

- `fettle -u` / `-a` now runs a **best-effort security gate** before a real upgrade:
  it reads the **cached** advisory data (never fetches, never blocks/fails a routine
  update on missing/stale/offline data), prints a one-line security summary, and — if
  `[advisories] warn_gate` is on (default) and **Critical** CVEs are currently
  unpatched — asks one extra confirmation before proceeding. Skipped under `--yes`
  (unattended never stalls) and on `--dry-run`.

## [0.17.0] — security-advisory / CVE tracking, Arch/Manjaro (Phase 19 M1)

- New opt-in **`fettle advisory-check`** (Arch/Manjaro; Debian/Ubuntu planned) — for
  each installed package it reports known CVEs with **a fix you haven't applied yet**,
  and — the distinctive part — CVEs it's **currently vulnerable to with no fix released
  yet** (a heads-up *before* an advisory/patch exists). The AUR RPC / package manager
  can't surface either.
- Bulk-fetches `security.archlinux.org` into a **rebuildable SQLite cache**
  (`~/.cache/fettle/advisories.db`; `sqlite3` is stdlib, so the zero-dependency core
  holds), refreshed on-run when stale, or on demand via **`fettle advisory-update`**.
  Version comparison is delegated to `vercmp` (never hand-rolled).
- Report: a **"Pending fixes"** callout (vulnerable, no fix yet) above a
  severity-banded **"Fix available"** table, plus the packages the tracker **doesn't
  cover** (AUR/manual/foreign) so a clean result never over-reassures. Rendered in the
  HTML dashboard too. On Manjaro, "fix available" is phrased as possible sync-lag, not
  alarm. New `[advisories]` config (`cache_ttl`, `severity_threshold`,
  `exclude_packages`, `exclude_classes`, `warn_gate`), all quiet defaults.
- Read-only, opt-in (never in the default `-a` set).

## [0.16.0] — aur-audit: reverse-dependents ("nothing uses this") check

- `-A` (`aur-audit`) now flags foreign packages that **nothing on the system depends
  on** — the AUR RPC can't surface this, so a healthy-but-leftover clone (e.g. an old
  `webkit2gtk` that nothing links) previously looked perfectly fine. For every foreign
  package it reads `pacman -Qi` reverse-deps and adds a graded flag: **`NO-DEPENDENTS`**
  (nothing requires *or* optionally-needs it), **`NO-HARD-DEPS`** (only an optdep of
  something), and **`LIB`** when it ships a public `/usr/lib/*.so` — so an unused
  *library* (the actionable case) reads `NO-DEPENDENTS LIB`. A **"Candidates for
  removal"** section (text + HTML, libraries first) lists the strong ones with a
  `sudo pacman -Rns <pkg>` hint and the caveat that **pacman only tracks packaged
  dependents** (unpackaged software / `dlopen` could still use them — verify first).
  The JSON gains `required_by`/`optional_for`/`is_library` per package and a
  `removal_candidates` list. `-A` stays read-only — it advises, never removes.

## [0.15.2] — web UI: controls on top

- The `/run` and `/remote` pages now put the **action controls at the top** of the
  page with the live **output log below** them (they were under the log before, so
  the options were pushed off-screen).

## [0.15.1] — web UI: run history

- **Run history (`/history`):** a new page (linked from the toolbar) listing every
  stored run across all hosts, newest first — `when · host · fettle <argv> · ok/exit`
  — each expandable to its full transcript. Reads the `fettle.log/1` run-logs the CLI
  already writes, including web-triggered runs.

## [0.15.0] — web UI (`fettle web`, beta)

An optional NiceGUI web interface over the fettle CLI. Strictly opt-in and
localhost-only; the CLI core stays pure-stdlib.

- New optional **`fettle web`** command serves a NiceGUI web UI (localhost-only by
  default). It's strictly opt-in: `pip install 'fettle[web]'`. The CLI core stays
  **pure-stdlib** (`dependencies = []`) — only `fettle/web/` imports nicegui, and a
  test enforces that importing the core never pulls it in, so the stdlib-only remote
  zipapp is unaffected. Without the extra, `fettle web` prints a friendly install
  hint instead of a traceback.
- **Live dashboard (Phase 1):** the web UI mirrors `fettle report` exactly — it
  serves the *same* HTML, generated live from the current `~/.fettle` on each load
  (no disk write), for all hosts at once, via the real report renderers. Served as a
  plain page with a small injected toolbar (**run** + **refresh**), so the report's
  own terminal CSS/JS (filter, collapse) work untouched.
- **Run read-only audits (Phase 2):** a `/run` page (linked from the dashboard) with
  a button per read-only audit (`pkg-audit`, `aur-audit`, `aur-ioc-scan`,
  `hardening-audit`, `config-drift`, `auto-updates`, `only-update`). Clicking one
  runs it as an unprivileged `python -m fettle <action>` subprocess and **streams the
  output live**; when it finishes, reload the dashboard to see the new report.
- **Run system-modifying actions (Phase 3):** the `/run` page also drives the
  privileged actions (`update`, `clean`, `orphans`, `kernel`, `rebuild-check`,
  `python-rebuild-check`, `firmware`, and the full `-a` set). Each has a **Preview**
  (a no-sudo `--dry-run`) and a **Run (sudo)** that first shows a **confirmation**
  and then runs `sudo -S fettle <action> --yes` with a sudo password you type on the
  page (held in memory only, never stored or logged, never on the command line),
  streaming the output live. The web server itself stays unprivileged. Note: some
  flows (AUR helpers / pamac) may prompt for a password separately.
- **Remote hosts & groups (Phase 4):** a `/remote` page lists the configured
  `[remote.groups.<name>]` (with their hosts) and takes an ad-hoc host, with an
  actions field (default `-a`). **Preview** runs `fettle remote <target> … --dry-run`
  (safe); **Run** confirms, then `fettle remote <target> … --yes` over SSH, streaming
  the per-host output. Remote hosts elevate themselves over SSH (no local sudo);
  `--yes` uses non-tty SSH, so it needs passwordless sudo on the targets. Fetched-back
  per-host reports then appear under each host on the dashboard.
- **Hardening (Phase 5):** binds `127.0.0.1` by default and rejects any request whose
  `Host` header isn't localhost (defends a privileged local tool against
  DNS-rebinding / cross-origin drive-by). Every web-triggered action is recorded in
  `~/.fettle/web-actions.log` (`0600`; the command line only, never the password).
  Networked/multi-user access with authentication is intentionally out of scope for
  now — run it behind your own auth if you expose it.

## [0.14.0] — AUR reports link packages + say what they are

- **In the HTML report, AUR package names are now links to their AUR page**
  (`aur.archlinux.org/packages/<name>`) — in the AUR Package Health report *and* in
  the supply-chain (`pkg-audit`) and IOC-scan (`aur-ioc-scan`) findings. Only AUR
  packages are linked; `apt`/`flatpak`/`snap` names (no AUR page) stay plain text.
- **The AUR Package Health table gains a "software" column** — the AUR one-line
  description (truncated, full text on hover) plus a `↗ homepage` link to the
  upstream project. Both come from data fettle already fetches (the AUR RPC
  response), so there are **no new network calls**. Upstream URLs are gated to
  `http(s)` before becoming a link (a malicious `javascript:` URL is never emitted).
  The plain-text `.txt` report is unchanged.

## [0.13.3] — `fettle remote -h` docs refresh

- `fettle remote -h` now documents **host groups** (`HOST|GROUP` grammar + how a
  `[remote.groups.<name>]` runs each host in order) — the help predated the groups
  feature — and points at the **current** report location
  (`~/.fettle/{reports,logs}/<host>/`, with the run-log now fetched back too) instead
  of the stale pre-0.11 `~/upgrade-check-<host>.txt` path. Main `--help` and an
  internal docstring got the same path correction. No behavior change.

## [0.13.2] — no ncurses over SSH; show each report's command

- **Debian/Ubuntu upgrades no longer pop a full-screen ncurses dialog.** `apt`'s
  `needrestart` service-restart menu and any `debconf` config screen used to take
  over the terminal (and corrupt it — wrapped, single-line output — especially over
  `ssh -t` under the run-log recorder). fettle now runs the upgrade with
  `NEEDRESTART_MODE=l` (needrestart *lists* what needs restarting instead of
  prompting; fettle already surfaces `sudo needrestart` as a next step) and a
  plain-text `debconf` frontend (`DEBIAN_FRONTEND=readline` interactively,
  `noninteractive` under `--yes`). `apt` still asks its own `[Y/n]` in the default
  (non-`--yes`) mode.
- **The HTML report shows the exact command that produced each report.** Every
  report records the `fettle …` invocation that created it (e.g. `fettle -H`), shown
  as a `$ fettle -H` chip on the entry. Recorded per host, so a fetched remote
  report shows how it was produced *there*. Pre-0.13.2 reports simply omit the chip.

## [0.13.1] — group runs show under each target host

- **A group run's per-host result now shows under that host in the HTML report.**
  After a remote (or group) run, fettle fetches back not just the host's reports but
  also its **own run-log** (its session transcript, including the package-update
  output) into `~/.fettle/logs/<host>/`. So `fettle remote bifrost-lab -a` produces
  a "Session Transcripts (run logs)" entry under **each** of bifrost/ec1/ec2/ec3 —
  the actual `fettle -a` run that happened on that host.
- **The "group runs" area is now a tiny pass/fail summary**, not a transcript dump:
  one line per `fettle remote <group>` session (when · command · ok/exit badge).
  The detail lives under each host, where the previous bullet now puts it.

## [0.13.0] — remote host groups

- **`fettle remote <group>` runs on a whole group of hosts, one by one.** Define a
  group in the config and update the entire lab with one command:
  ```toml
  [remote.groups.bifrost-lab]
  hosts = ["bifrost", "ec1", "ec2", "ec3"]   # + optional actions / ssh_args / yes
  ```
  `fettle remote bifrost-lab -a` runs `fettle -a` on each host **in order** (same
  per-host flow, including the report fetch-back), **confirms the host list** first
  (skipped under `--yes` / `--dry-run`), **continues past a failing host**, and
  prints a **pass/fail summary** (non-zero exit if any host failed). A group can set
  per-group default `actions`, `ssh_args`, and `yes`; a bare host list is shorthand.
  A group name wins over a same-named single host. For a walk-away run, use `--yes`
  with passwordless (`NOPASSWD`) sudo on the hosts.
- In the HTML report, a group is **not** shown as a host asset: each host in the
  group keeps its own dashboard card/section (results are fetched back per host),
  and the group's orchestration transcript appears in a separate "group runs" area.

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
  per-type counts, latest run), collapsible sections (with a `[+]`/`[-]` expand
  affordance) grouped by report type with native rendering (scored hardening
  tables, severity-coloured findings, upgrade verdicts, package lists, log
  transcripts), and a host/type/text filter. **Empty reports** (a clean
  `obsolete-pkgs`, an `aur-ioc-scan` with no indicators, …) are hidden, with a
  per-host "N hidden" note. Styled as a **dark Linux terminal** (monospace, phosphor
  palette, shell-prompt header). Pure stdlib, no external assets. `fettle report
  --open` opens it in a browser.
  *This is a first cut — the layout and contents will evolve; feedback welcome.*
- **`fettle report --backfill-json`** — one-off converter that gives pre-0.12
  `.txt` reports/logs a JSON sibling (idempotent, non-destructive) so the dashboard
  is populated without re-scanning.
- Remote report fetch-back now pulls the `.json` siblings too.
- **`sys-audit` now writes a report** (`~/.fettle/reports/<host>/sys-audit-<ts>.{txt,json}`),
  so the firmware/boot/hardware scan shows up in the HTML dashboard alongside the
  other reports — previously it only printed to the terminal. Every scanned
  category is captured (even ones whose detail comes from raw command output, not
  status lines), with per-item status levels **and a full raw-output section**.
  `fettle sys-audit remote <host>` fetches its report back to the controller.

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
