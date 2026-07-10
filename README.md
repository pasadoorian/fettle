# fettle

> # **⚠️ NOTE: THIS IS BETA CODE — USE AT YOUR OWN RISK.**

> *in fine fettle* — in good working order.

**fettle** is a cross-distribution Linux system-maintenance and supply-chain tool.
One command surface keeps your machine updated and clean, audits where your
software came from and whether it has been tampered with, and scans the firmware /
boot chain for security posture — on Arch/Manjaro and Debian/Ubuntu alike.

It is the Python successor to the Arch/Manjaro `update.sh`, `aur-precheck.sh`, and
`supply_chain_check.sh` scripts (from
[`linux_hacks`](https://github.com/pasadoorian/linux_hacks)), rebuilt around a
pluggable per-distro backend so a new distribution is a single new class, and with
real unit-test coverage the bash originals never had.

- **Pure Python standard library** — zero third-party runtime dependencies.
- **Python 3.11+** (uses `tomllib`).
- Nothing to `pip install`: a tiny launcher runs the checked-out repo in place.

---

## Contents

- [What it does](#what-it-does)
- [Supported distributions](#supported-distributions)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Maintenance actions](#maintenance-actions)
- [Package supply-chain](#package-supply-chain)
- [System supply-chain — `sys-audit`](#system-supply-chain--sys-audit)
- [Configuration](#configuration)
- [Common options](#common-options)
- [How elevation works](#how-elevation-works)
- [Architecture](#architecture)
- [Development](#development)
- [Changelog](#changelog)
- [License](#license)

---

## What it does

fettle has three feature families:

1. **Maintenance** — update packages, clean caches, prune orphans, check for
   rebuilds/service-restarts, review config-file drift, apply firmware updates,
   and manage kernels.
2. **Package Supply Chain** — *where software came from and whether it's tampered*:
   third-party repos/PPAs, publishers, staleness, sandbox permissions, installed-
   file integrity, and (for the AUR) live malware-IOC feeds. Exposed as
   `pkg-audit`, plus the Arch-specific `aur-audit` / `aur-ioc-scan` and the
   install-time yay hook.
3. **System Supply Chain** — *the machine's firmware/boot/hardware posture*:
   Secure Boot, BIOS/UEFI, TPM, Intel ME, CPU microcode, package integrity,
   hardware and storage firmware. Exposed as `sys-audit`, runnable locally or over
   SSH.

The two supply-chain families are deliberately kept distinct in code, docs, and
CLI: "where did this software come from / is it tampered?" → **Package**
(`pkg-audit`); "is the machine's firmware/boot sound?" → **System** (`sys-audit`).

## Supported distributions

| Family | Backend | Package tooling | Detected `ID` / `ID_LIKE` |
|---|---|---|---|
| Arch / Manjaro | `arch` | pacman + yay/pamac + AUR | `arch`, `manjaro`, `endeavouros`, … |
| Debian / Ubuntu | `debian` | apt/nala + flatpak + snap | `debian`, `ubuntu`, `linuxmint`, `pop`, … |

Detection reads `/etc/os-release` and falls through the `ID_LIKE` chain, so
derivatives resolve to their parent family with no extra code. Override with
`--distro <name>` (handy for dry-runs of another backend).

## Requirements

Only **Python 3.11+** and **git** are mandatory. Everything else is optional:
fettle never installs tools — it detects what's present and **skips what's missing
with a note**, so you install only what the commands you actually use need.

### Maintenance

| | Arch / Manjaro | Debian / Ubuntu |
|---|---|---|
| AUR / extras | `yay` or `pamac` | — |
| rebuilds | `rebuild-detector` (`checkrebuild`) | `needrestart` |
| config drift | `pacman-contrib` (`pacdiff`) | (built-in `dpkg`) |
| orphans | (built-in) | `deborphan`, `apt-show-versions` |
| firmware | `fwupd` | `fwupd` |
| kernels | `mhwd-kernel` (Manjaro) | (built-in `dpkg`) |
| flatpak / snap | — | `flatpak`, `snapd` |

### `pkg-audit` (package supply-chain)

Nothing extra is *required* — the AUR audit uses only `pacman` + the network, and
the APT/Flatpak/Snap providers read config you already have.

| | Arch / Manjaro | Debian / Ubuntu |
|---|---|---|
| standard | *(none — uses `pacman`)* | `debsums` (file integrity); `flatpak`, `snapd` if you use them |
| manual | *(none)* | *(none)* |

### `sys-audit` (system supply-chain)

**Standard packages** (install what you want covered; missing ones are skipped):

```sh
# Arch / Manjaro
sudo pacman -S --needed mokutil efitools dmidecode inxi lshw pciutils \
    tpm2-tools smartmontools cpuid fwupd pacutils

# Debian / Ubuntu
sudo apt install mokutil efitools dmidecode inxi lshw pciutils \
    tpm2-tools smartmontools cpuid fwupd debsums
```

Which check uses what: `secureboot` → `mokutil`/`efitools` (+ systemd's `bootctl`);
`bios`·`hardware` → `dmidecode`,`inxi`,`lshw`,`pciutils`,`cpuid`; `fwupd` → `fwupd`;
`intel-me` → `pciutils`; `tpm` → `tpm2-tools`,`dmidecode`; `storage` →
`smartmontools`; `packages` → `pacutils` (`paccheck`) on Arch / `debsums` on Ubuntu.

**Manual tools** (not in standard repos — the checks degrade to advice without
them). fettle looks for each under `/opt/<name>/`, `/usr/share/<name>/`, and
`~/<name>/`:

| Check | Tool | Get it |
|---|---|---|
| `firmware` | **chipsec** (`chipsec/chipsec_main.py`) | Arch: AUR `chipsec`; else `git clone https://github.com/chipsec/chipsec` |
| `intel-me` | **Intel CSME Version Detection Tool** (`intel_csme/intel_csme_version_detection_tool`) | download from Intel |
| `tpm` | **tpm-vuln-checker** (`tpm-vuln-checker/tpm-vuln-checker`) | `git clone https://github.com/google/tpm-vuln-checker` |

Example: `git clone https://github.com/google/tpm-vuln-checker ~/tpm-vuln-checker`
puts the tool where the `tpm` check will find it.

## Installation

fettle is pure standard library, so there is nothing to build or `pip install` —
the launcher puts the repo on `PYTHONPATH` and runs `python3 -m fettle`.

```sh
git clone https://github.com/pasadoorian/fettle.git ~/src/fettle
ln -s ~/src/fettle/bin/fettle ~/.local/bin/fettle    # ensure ~/.local/bin is on PATH
fettle --help
```

Update with a plain `git pull`. To drop it in for the old updater:

```sh
ln -sf ~/src/fettle/bin/fettle ~/update.sh
```

### Optional: yay install-time supply-chain hook (Arch/Manjaro)

An advisory, **warn-only** AUR pre-flight that fires at install time — flagging
orphaned / out-of-date / stale packages, known-compromised names, and malicious
maintainers — on top of yay's built-in build-file review. It never blocks an
install.

```sh
cp ~/src/fettle/contrib/yay-init.lua ~/.config/yay/init.lua
```

The hook calls `fettle aur-precheck <pkg>` under the covers; you can run that
directly too.

## Quick start

```sh
fettle                     # run the default maintenance set (auto-elevates)
fettle -a --dry-run        # preview the whole default set; change nothing
fettle -c -u               # clean, then upgrade packages (short flags)
fettle clean update        # identical — every action also works as a bare word
fettle upgrade             # `upgrade` is a synonym for `update`
fettle -O                  # refresh metadata + report upgradable (no upgrade; safe)
fettle -A                  # AUR health audit  -> ~/aur-audit.txt
fettle -P                  # package supply-chain audit -> ~/pkg-audit.txt
fettle -S                  # full security scan (sys-audit --all; self-elevates)
fettle -U                  # AI: is this upgrade safe? [experimental] (needs API key)
```

## Maintenance actions

Run with no action to execute the configured default set. Actions can be given as
short flags, long flags, or bare words (`fettle -c -u` == `fettle clean update`).
Anything a distro's backend doesn't support is skipped with a note.

| Flag | Action | Arch | Debian |
|---|---|---|---|
| `-c` | `clean` | pacman + pamac/yay caches (**asks first**; `--yes` skips) | `apt-get clean`/`autoclean`, unused flatpaks, disabled snap revisions (**asks first**) |
| `-o` | `orphans` | foreign pkgs → `~/alien-pkgs.txt`; remove true orphans (`-Qtdq`) | obsolete pkgs → `~/obsolete-pkgs.txt`; `deborphan` + `autoremove` |
| `-u` / `--upgrade` | `update` | pacman/pamac, then yay AUR (with review) | apt/nala, then flatpak, then snap |
| `-O` | `only-update` | refresh metadata **safely** (private cache; no `pacman -Sy`) + report upgradable | `apt update` + flatpak metadata, then report upgradable |
| `-r` | `rebuild-check` | `checkrebuild` (rebuild with `-R`) | `needrestart` (services to restart) |
| `-y` | `python-rebuild-check` *(arch)* | rebuild pkgs stranded on an old `/usr/lib/python3.X` | — (apt handles transitions) |
| `-d` | `config-drift` | `pacdiff` `.pacnew` files | `*.dpkg-dist`/`*.dpkg-new`/`*.ucf-dist` + `dpkg --audit` |
| `-f` | `firmware` | `fwupdmgr` (shared) | `fwupdmgr` (shared) |
| `-k` | `kernel` | `mhwd-kernel` (running protected) | `dpkg -l 'linux-image-*'`, purge old (running protected) |
| `-A` | `aur-audit` *(arch)* | AUR health table → `~/aur-audit.txt` | — |
| `-I` | `aur-ioc-scan` *(arch)* | scan installed AUR pkgs for IoCs → `~/aur-ioc-scan.txt` | — |
| `-P` | `pkg-audit` | package supply-chain audit → `~/pkg-audit.txt` | apt/flatpak/snap provenance |

`update` **asks before upgrading** (the package manager shows its plan and
prompts); pass `--yes` to skip the confirmation and run non-interactively.

Three more flags are **shortcuts to subcommands** (not part of the action
pipeline): `-S` → `sys-audit --all` (security scan), `-U` → `upgrade-check` (AI
advisor), `-p` → `aur-precheck` (AUR pre-flight; bare = scan all installed). Use
the subcommand form for their own options.

**Default set** (run when you pass no action, or `-a`/`--all`): clean, orphans,
update, rebuild-check, python-rebuild-check, config-drift, firmware-check.
Excluded from the default set — request explicitly: `-O`, `-k`, `-A`, `-I`, `-P`.

`-R` / `--auto-rebuild` turns the `-r` / `-y` checks from "list" into "offer to
rebuild". Destructive steps (orphan/kernel removal, disabled-snap pruning) always
prompt per item unless you pass `--yes`.

## Package supply-chain

Four commands touch package provenance/safety and are easy to confuse. Rule of
thumb: **`-P` is the broad, all-ecosystem one; `-A`/`-I`/`-p` are AUR-only and each
answers a different question.**

| Command | What it answers | Use it when | Output |
|---|---|---|---|
| `fettle -P` / `pkg-audit` | Across **all** ecosystems (AUR/APT/Flatpak/Snap): where did my installed software come from, and has it been tampered with? | you want one whole-system supply-chain report | findings → `~/pkg-audit.txt` |
| `fettle -A` / `aur-audit` *(arch)* | AUR **health census**: age, votes, out-of-date, orphan, recently-changed, maintainer-change (re-adoption tell) | you want to vet how well-maintained your AUR pkgs are | table → `~/aur-audit.txt` |
| `fettle -I` / `aur-ioc-scan` *(arch)* | AUR **threat sweep**: do any installed AUR pkgs match known-compromise feeds (bad package names, malicious maintainers, malicious JS-cache traces)? | you want a known-compromise check (lenucksi IoC feed) | findings → `~/aur-ioc-scan.txt` |
| `fettle -p` / `aur-precheck` *(arch)* | AUR **pre-install / quick sweep**: is this package (or every installed AUR pkg) risky right now — orphaned, out-of-date, stale, compromised name, malicious maintainer? | before building an AUR pkg (the yay hook), or a fast all-installed check | `CRIT`/`WARN` lines |

`pkg-audit` runs each provider whose package manager is present and reports one
normalized `Finding` format with one severity language:

- **AUR** (Arch): orphan / out-of-date / stale / known-bad via AUR RPC + IOC feed.
- **APT** (Debian): third-party repos/PPAs, `[trusted=yes]`, third-party-http,
  `debsums` file integrity.
- **Flatpak**: non-flathub origin, broad sandbox permissions (host/home
  filesystem, `devices=all`), http remotes.
- **Snap**: sideloaded / unverified publisher, `classic`/`devmode` confinement.

Each provider prints a **coverage line** so uneven depth is explicit — a real
malware/IOC feed exists only for the AUR, and fettle never pretends otherwise.

`fettle aur-precheck <pkg>…` is the install-time helper (used by the yay hook): it
prints machine-readable `CRIT`/`WARN` lines for the named packages and always exits
0. **With no package named** (`fettle aur-precheck` or `fettle -p`) it scans *every*
installed AUR package instead — a quick safety sweep. Tunable via env vars
(`AUR_PRECHECK=false` to disable, `AUR_PRECHECK_MAX_AGE_DAYS`, `YAY_ALLOWLIST_FILE`, …).

How it differs from the others: `aur-precheck` is the fast, self-contained,
env-driven per-package gate (no config/TOML load, silent when clean — built for the
hook); `aur-audit` is the detailed health *report*; `aur-ioc-scan` is the pure
threat/IoC sweep; `pkg-audit` is the cross-ecosystem umbrella that folds AUR
health+IoC in alongside APT/Flatpak/Snap.

## System supply-chain — `sys-audit`

A port of the Eclypsium firmware/boot-chain cheat-sheet. Most checks need root, so
`sys-audit` **elevates itself** (prompting for sudo) — just run `fettle sys-audit`,
**no `sudo` prefix needed**. Pass `--user` to stay unprivileged (partial results).

```sh
fettle sys-audit --list              # list categories (no elevation)
fettle sys-audit --all               # run everything (prompts for sudo)
fettle sys-audit secureboot tpm      # run specific categories
fettle sys-audit -v microcode        # verbose (raw tool output)
fettle sys-audit --user hardware     # run as your user, no sudo
```

> **`sudo: fettle: command not found`?** Don't prefix `sudo` — `fettle` lives in
> `~/.local/bin`, which isn't on root's `PATH`. fettle elevates itself, so plain
> `fettle sys-audit …` works. (If you *want* `sudo fettle` to work, also symlink it
> onto a system path: `sudo ln -sf ~/src/fettle/bin/fettle /usr/local/bin/fettle`.)

| Category | Checks |
|---|---|
| `secureboot` | Secure Boot state + the **2026 Microsoft cert-expiry matrix** (2011 vs 2023 KEK/db certs, migration status) |
| `bios` | BIOS/UEFI vendor, version, date; motherboard info |
| `firmware` | chipsec — Intel ME manufacturing mode, BIOS write-protection (needs chipsec + root) |
| `fwupd` | firmware devices, available updates, HSI security attributes |
| `intel-me` | MEI device, ME firmware version, ME PCI controller |
| `microcode` | CPU microcode revision + `/sys` vulnerability mitigations |
| `tpm` | TPM device, version, DMI info, TPM2 capabilities |
| `packages` | installed-file integrity (`paccheck`/`pacman -Qkk`, or `debsums`/`dpkg --verify`) |
| `hardware` | inxi/lspci hardware inventory, memory modules |
| `storage` | per-device model / firmware / serial via `smartctl` |

### Remote scanning

Scan a host over SSH without installing anything on it. fettle builds a single-file
**zipapp** of itself (pure stdlib → runs under any `python3`), `scp`s it to the
target, runs it over `ssh -t`, and cleans up — preserving the remote exit code.
The target only needs a `python3` interpreter; the scanner doesn't read the TOML
config, so it runs fine on older Pythons (e.g. Ubuntu 22.04's 3.10, which has no
`tomllib`).

```sh
fettle sys-audit remote server1 all               # host from ~/.ssh/config
fettle sys-audit remote --sudo admin@host2 tpm    # prompt once for remote sudo
fettle sys-audit remote -v gateway secureboot     # -v forwarded to the remote run
```

## Remote maintenance

Run **any** action on another host over SSH — same zipapp transport as the scanner
(nothing installed on the target; it just needs `python3` and the same fettle
version). The grammar is:

```
fettle remote [--ssh-arg ARG]... HOST [any fettle action/flags...]
```

Everything after `HOST` is forwarded verbatim to fettle on the remote, so the full
CLI works remotely. Changes are wrapped in `sudo` (the remote fettle runs as root);
a `--dry-run` needs neither sudo nor a password.

```sh
fettle remote server1                  # safe default: clean + update + firmware-check
fettle remote server1 -c -u            # clean, then upgrade packages
fettle remote server1 update --dry-run # preview an update; changes nothing
fettle remote server1 -a --yes         # the full default set, unattended
fettle remote server1 -S               # security scan on the host (sys-audit --all)
fettle remote server1 orphans kernel   # destructive actions run only when named
fettle remote --ssh-arg=-oConnectTimeout=5 server1 -u
```

- **Safe by default.** `fettle remote <host>` with **no action named** runs only
  `clean update firmware-check` — even with `--yes`. Destructive/interactive
  actions (**orphan** and **kernel** removal) run **only when you name them**; `-a`
  forwards through and runs the remote's full default set.
- **`-U`/upgrade-check** runs on the *remote* and needs `ANTHROPIC_API_KEY` set
  there (your local key is not forwarded) — fettle warns you when you use it.
- **Asks before upgrading.** By default the run is interactive over an `ssh -t`
  TTY: the remote package manager shows its plan and prompts before upgrading (and
  sudo prompts for a password if needed). This is the same locally — `fettle -u`
  asks; it does **not** auto-upgrade.
- **`--yes` = fully unattended.** No prompts at all: `pacman --noconfirm` /
  `apt-get … --force-confold full-upgrade -y` (keeps old conffiles), no TTY. It
  assumes **passwordless sudo** on the target, and on Arch it **skips yay's
  PKGBUILD review** — only use it on hosts whose sources you trust.

> After an unattended (`--yes`) run, review kept config files with
> `fettle remote <host> config-drift` (apt keeps the old file and drops a
> `.dpkg-dist`; pacman leaves a `.pacnew`).

A standalone binary (for hosts with no `python3` at all) is a planned option; the
zipapp is the current transport.

## Upgrade Checker (AI) — experimental

> ⚠️ **Experimental / under active testing.** This feature is still being validated
> across VMs and distros. Treat its advice as a **second opinion**, not a guarantee —
> read the cited forum threads and use your own judgment before upgrading.

`fettle upgrade-check` asks **Claude** whether a pending upgrade is safe *before*
you run it. It collects the packages that would upgrade plus a hardware/software
profile (`inxi`), has Claude research the distro's forums (Arch BBS, Manjaro,
Ubuntu Forums, Launchpad) for known issues, and returns a clean, cited verdict with concrete
before/after steps. It is **report-only** — it never touches your system; you run
`fettle -u` yourself once you're satisfied.

```sh
export ANTHROPIC_API_KEY=sk-ant-…
fettle upgrade-check                 # verdict + steps -> ~/upgrade-check.txt
fettle upgrade-check --effort high   # deeper analysis for a big/risky upgrade
fettle upgrade-check --no-web        # skip forum search (faster, cheaper)
```

- **API key** (first found wins): `ANTHROPIC_API_KEY` env → `ai_api_key` in the
  config. Prefer the env var. If you put the key in the config, **`chmod 600` it
  yourself** — fettle refuses a world-*writable* config but does **not** reject a
  world-*readable* one, so a default `644` file leaks the key to other local
  users. No key → it just prints the pending-package list. `--print-config`
  **never** prints the key in full — only a `sk-ant-…1234` hint and its source.
- **Privacy:** hardware **serials, MAC addresses, and UUIDs are stripped** from the
  inxi output before anything is sent; only the redacted profile + package list
  reach the API.
- **Grounded, not guessed:** the model is given the real package list and told to
  cite a forum source for every claim (and to call the upgrade routine when it
  finds nothing). fettle then **drops any flagged package that isn't actually
  upgrading** and any source outside the trusted forums — so the report can't warn
  you about things that aren't in your update.
- **Cost & controls:** one request per run — `claude-sonnet-5` at `effort=medium`,
  forum searches capped at `ai_max_web_searches` (default 5). Roughly
  **$0.10–0.30 for a small upgrade**, up to **~$0.60 for a large batch** (a
  330-package Ubuntu run with 5 web searches was ~186k input / 7k output tokens),
  since the fetched forum pages ride in the input. The exact token + search count
  prints at the end. Tune via config (`ai_model`, `ai_effort`,
  `ai_max_web_searches`), `--effort`, or `--no-web` (cheapest — skips the forum
  search entirely).

Pure stdlib, like everything else — the API is called over `urllib`, no
`anthropic` SDK to install (which also means no `pip`/venv friction on Arch).

## Configuration

Optional TOML file at `~/.config/fettle/config.toml`. Precedence, low → high:
**built-in defaults < config file < command-line flags**. fettle refuses to read a
config that is world-**writable** or owned by someone other than you or root — it
does **not** reject a world-**readable** one, so `chmod 600` it yourself if it
holds a secret. Action names accept hyphens or underscores.

```toml
# ~/.config/fettle/config.toml  (all keys optional; values shown are the defaults)

default_actions = ["clean", "orphans", "update", "rebuild-check", "python-rebuild-check", "config-drift", "firmware-check"]
auto_rebuild    = false
exclude_foreign = ["brave-bin", "google-chrome"]   # names or globs; skip in reports
keep_orphans    = ["downgrade", "nvchecker"]        # never offer these for removal

# AUR supply-chain
aur_max_age_days  = 365    # PKGBUILD older than this is "stale" (pkg-audit)
aur_recent_days   = 21     # -A flags packages changed within this window
aur_ioc_campaigns = ["aur-infected", "chaos-rat", "russian-spam"]
aur_ioc_cache_ttl = 21600  # seconds to cache IOC feeds on disk

# Upgrade Checker (fettle upgrade-check) [experimental] — prefer ANTHROPIC_API_KEY env var
ai_model            = "claude-sonnet-5"
ai_effort           = "medium"   # low | medium | high — thinking depth vs cost
ai_max_web_searches = 5          # cap forum searches per run (bounds tokens/cost)
# ai_api_key = "sk-ant-..."      # optional; keep the file chmod 600; never printed in full

# Per-distro tool selection
[updaters.arch]
system_updater = "pacman"   # pacman | pamac
aur_updater    = "yay"      # yay | pamac | none

[updaters.debian]
system_updater  = "apt"      # apt | nala | none
flatpak_updater = "flatpak"  # flatpak | none
snap_updater    = "snap"     # snap | none
```

`fettle --print-config` shows the effective configuration; `--config PATH` points
at an alternate file; `--no-config` ignores it entirely. A starter template ships
as [`fettle.toml.example`](fettle.toml.example).

## Previewing an upgrade

`fettle -u --dry-run` resolves and lists **every package the upgrade would
install** — version upgrades, the new dependencies they pull in, and any
removals — grouped by source, before it prints the commands it would run. It
changes nothing and needs no `sudo`.

```
▸ [1/1] Updating packages
  14 package(s) would be installed/changed:
    official repos (12):
      linux              6.12.1-1 -> 6.12.4-1
      systemd            257.2-1  -> 257.3-1
      + libfoo           2.0-1                 (new dependency)
      - obsolete-lib     1.2-3                 (remove)
      …
    AUR (2):
      brave-bin          1:1.92.134-1 -> 1:1.92.138-1
  would run: pacman -Syuu
  …
```

On Arch this uses `checkupdates`' trick — a throwaway package DB synced in `/tmp`
via `fakeroot` — so the preview reflects **fresh** mirror data without touching
your system DB or needing root (`pacman-contrib` + `fakeroot` recommended; it
degrades to cached data with a note otherwise). On Debian/Ubuntu it's apt's
native `apt-get -s dist-upgrade` simulation. Pass `--no-sync` to skip the refresh
and preview against the cached data (faster; may be stale). AUR `-git`/`-devel`
packages that rebuild from source may not show a version bump until yay fetches
them — noted in the output.

## Common options

| Option | Effect |
|---|---|
| `-a`, `--all` | run the default action set |
| `--dry-run` | print what would run; execute nothing (read-only queries still run) |
| `--no-sync` | dry-run preview: use cached repo data instead of a fresh sync |
| `--only ACTION` / `--skip ACTION` | restrict / exclude actions (repeatable) |
| `--yes` | assume yes to all prompts (non-interactive) |
| `-R`, `--auto-rebuild` | offer to rebuild instead of only listing (with `-r`/`-y`) |
| `-v` / `-q` / `--no-color` | verbose / quiet / disable color (also honors `NO_COLOR`) |
| `--distro NAME` | override distro detection |
| `--print-config` / `--version` | print config or version and exit |

## How elevation works

fettle elevates **lazily and by itself** — you never need to type `sudo fettle`.

- **Maintenance actions** re-exec under `sudo` only when a selected action will
  actually change the system. Read-only work — `pkg-audit` (`-P`), `aur-audit`
  (`-A`), `aur-ioc-scan` (`-I`), `config-drift` (`-d`) — runs unprivileged and
  never prompts. `--dry-run` never elevates.
- **`sys-audit`** elevates itself too (most checks need root); pass `--user` to
  stay unprivileged. `--list` and `remote` don't elevate.

Because elevation re-execs the full `python3 -m fettle` path (not the `fettle`
name), it works even though the launcher in `~/.local/bin` isn't on root's `PATH`
— which is why `sudo fettle …` is unnecessary (and fails with *command not found*
unless you also install to a system path).

## Architecture

- **One backend per distro family** (`fettle/backends/*.py`) implementing a shared
  `PackageBackend` ABC; a backend advertises the actions it supports, and the CLI
  hides the rest. Adding a distro is one subclass + one registry line — never a
  new script.
- **Curated command allowlist** per backend: config tunes *behavior* (skip
  flatpak, pick nala), it never *discovers* new commands to run.
- **Normalized supply-chain model** (`fettle/supplychain/`): one `Finding` format
  and one seven-question set; each source provider answers what its ecosystem can
  and states its coverage.
- **Mockable seams**: all command execution goes through one `run()` wrapper, and
  the `sys-audit` checks read `/sys`·`/proc`·`/dev` through an injectable `root` —
  so the whole thing is unit-tested with no root and no real hardware.
- **Everything routes through one output layer** (`fettle/output.py`) for a single
  color / verbosity / summary language.

## Development

```sh
python -m venv venv && source venv/bin/activate
pip install -e '.[dev]'      # pytest + ruff (dev-only; runtime stays pure-stdlib)
pytest -q                    # full unit suite
ruff check fettle/ tests/    # lint
```

Tests mock external commands via `unittest.mock.patch("subprocess.run", …)` and
fake `/sys`·`/proc` trees with a `tmp_path` root, so they need neither root nor
special hardware. Runtime code never imports pytest — the shipped tool is
pure standard library.

## Changelog

### v0.4.2 — fixes

- **`fettle upgrade` now works** as a synonym for `update` (install package
  upgrades). The `--upgrade` flag already worked; the bare word didn't.

### v0.4.1 — fixes

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

### v0.4.0 — CLI rework (breaking)

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

## License

[MIT](LICENSE).
