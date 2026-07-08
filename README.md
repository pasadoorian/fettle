# fettle

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

- **Python 3.11+** and **git**.
- Whatever tools the actions you use need — fettle never installs them, it detects
  them and skips (with a note) what's missing. Typical extras:
  - *Arch:* `yay`/`pamac`, `rebuild-detector` (`checkrebuild`), `pacman-contrib`
    (`pacdiff`), `fwupd`, `mhwd-kernel` (Manjaro), `pacutils` (`paccheck`).
  - *Debian:* `nala`, `flatpak`, `snapd`, `deborphan`, `needrestart`,
    `apt-show-versions`, `fwupd`, `debsums`.
  - *sys-audit:* `mokutil`/`efitools`, `dmidecode`, `inxi`, `tpm2-tools`,
    `smartmontools`, `fwupd`, optionally `chipsec`.

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
fettle --all --dry-run     # show exactly what would run; change nothing
fettle -c -u               # clean + update (short flags)
fettle clean update        # same thing, as words
fettle -A                  # AUR health audit  -> ~/aur-audit.txt
fettle pkg-audit           # normalized package supply-chain audit
sudo fettle sys-audit --all   # full firmware/boot/hardware security scan
```

## Maintenance actions

Run with no action to execute the configured default set. Actions can be given as
short flags, long flags, or bare words (`fettle -c -u` == `fettle clean update`).
Anything a distro's backend doesn't support is skipped with a note.

| Flag | Action | Arch | Debian |
|---|---|---|---|
| `-c` | `clean` | pacman + pamac/yay caches | `apt-get clean`/`autoclean`, unused flatpaks, disabled snap revisions (asks first) |
| `-o` | `orphans` | foreign pkgs → `~/alien-pkgs.txt`; remove true orphans (`-Qtdq`) | obsolete pkgs → `~/obsolete-pkgs.txt`; `deborphan` + `autoremove` |
| `-u` | `update` | pacman/pamac, then yay AUR (with review) | apt/nala, then flatpak, then snap |
| `-r` | `rebuilds` | `checkrebuild` (rebuild with `-R`) | `needrestart` (services to restart) |
| `-y` | `python-rebuild` *(arch)* | rebuild pkgs stranded on an old `/usr/lib/python3.X` | — (apt handles transitions) |
| `-p` | `config-drift` | `pacdiff` `.pacnew` files | `*.dpkg-dist`/`*.dpkg-new`/`*.ucf-dist` + `dpkg --audit` |
| `-f` | `firmware` | `fwupdmgr` (shared) | `fwupdmgr` (shared) |
| `-k` | `kernels` | `mhwd-kernel` (running protected) | `dpkg -l 'linux-image-*'`, purge old (running protected) |

**Default set** (run when you pass no action, or `--all`): clean, orphans, update,
rebuilds, python-rebuild, config-drift, firmware. `-k`, `-A`, and `-S` are excluded
from the default/`--all` set and must be requested explicitly.

`-R` / `--auto-rebuild` turns the `-r` / `-y` checks from "list" into "offer to
rebuild". Destructive steps (orphan/kernel removal, disabled-snap pruning) always
prompt per item unless you pass `--yes`.

## Package supply-chain

Three distinct commands — do not confuse them:

| Command | Scope | Output |
|---|---|---|
| `fettle -A` / `aur-audit` *(arch)* | **Health census** of installed AUR pkgs: age, votes, out-of-date, orphan, recently-changed, and maintainer-change (re-adoption tell) | table → `~/aur-audit.txt` |
| `fettle -S` / `aur-ioc-scan` *(arch)* | **IoC scan** of installed AUR pkgs: known-malicious package names, malicious maintainer accounts, malicious JS-cache traces (lenucksi feed) | findings → `~/aur-ioc-scan.txt` |
| `fettle pkg-audit` | **Cross-distro** normalized audit merging every present source provider | findings → `~/pkg-audit.txt` |

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
prints machine-readable `CRIT`/`WARN` lines for a not-yet-installed package and
always exits 0. Tunable via env vars (`AUR_PRECHECK=false` to disable,
`AUR_PRECHECK_MAX_AGE_DAYS`, `YAY_ALLOWLIST_FILE`, …).

## System supply-chain — `sys-audit`

A port of the Eclypsium firmware/boot-chain cheat-sheet. **Run under `sudo`** for
the root-only data (dmidecode, chipsec, smartctl, package integrity); it degrades
gracefully and tells you what needs root.

```sh
fettle sys-audit --list              # list categories
sudo fettle sys-audit --all          # run everything
sudo fettle sys-audit secureboot tpm # run specific categories
fettle sys-audit -v microcode        # verbose (raw tool output)
```

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

```sh
fettle sys-audit remote server1 all               # host from ~/.ssh/config
fettle sys-audit remote --sudo admin@host2 tpm    # prompt once for remote sudo
fettle sys-audit remote -v gateway secureboot     # -v forwarded to the remote run
```

## Configuration

Optional TOML file at `~/.config/fettle/config.toml`. Precedence, low → high:
**built-in defaults < config file < command-line flags**. fettle refuses to read a
config that is world-writable or owned by someone other than you or root.

```toml
# ~/.config/fettle/config.toml  (all keys optional; values shown are the defaults)

default_actions = ["clean", "orphans", "update", "rebuilds", "python_rebuild", "config_drift", "firmware"]
auto_rebuild    = false
exclude_foreign = ["brave-bin", "google-chrome"]   # names or globs; skip in reports
keep_orphans    = ["downgrade", "nvchecker"]        # never offer these for removal

# AUR supply-chain
aur_max_age_days  = 365    # PKGBUILD older than this is "stale" (pkg-audit)
aur_recent_days   = 21     # -A flags packages changed within this window
aur_ioc_campaigns = ["aur-infected", "chaos-rat", "russian-spam"]
aur_ioc_cache_ttl = 21600  # seconds to cache IOC feeds on disk

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

## Common options

| Option | Effect |
|---|---|
| `-a`, `--all` | run the default action set |
| `--dry-run` | print what would run; execute nothing (read-only queries still run) |
| `--only ACTION` / `--skip ACTION` | restrict / exclude actions (repeatable) |
| `--yes` | assume yes to all prompts (non-interactive) |
| `-R`, `--auto-rebuild` | offer to rebuild instead of only listing (with `-r`/`-y`) |
| `-v` / `-q` / `--no-color` | verbose / quiet / disable color (also honors `NO_COLOR`) |
| `--distro NAME` | override distro detection |
| `--print-config` / `--version` | print config or version and exit |

## How elevation works

fettle elevates **lazily**: it re-execs under `sudo` only when a selected action
will actually change the system. Read-only work — `pkg-audit`, `aur-audit` (`-A`),
`aur-ioc-scan` (`-S`), and `config-drift` (`-p`) — runs unprivileged, so those
never prompt for a password. `--dry-run` never elevates. `sys-audit` does not
auto-elevate; run it under `sudo` yourself for complete results.

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

## License

[MIT](LICENSE).
