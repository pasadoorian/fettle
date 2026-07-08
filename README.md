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
fettle --all --dry-run     # show exactly what would run; change nothing
fettle -c -u               # clean + update (short flags)
fettle clean update        # same thing, as words
fettle -A                  # AUR health audit  -> ~/aur-audit.txt
fettle pkg-audit           # normalized package supply-chain audit
fettle sys-audit --all     # full security scan (elevates itself; no sudo needed)
fettle upgrade-check       # AI: is this upgrade safe? [experimental] (needs API key)
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

`update` **asks before upgrading** (the package manager shows its plan and
prompts); pass `--yes` to skip the confirmation and run non-interactively.
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

Run maintenance on another host over SSH — same zipapp transport as the scanner
(nothing installed on the target; it just needs `python3`). The remote invocation
is wrapped in `sudo`, so the remote fettle runs as root.

```sh
fettle remote server1 -a               # safe default: clean + update + firmware
fettle remote server1 -a --dry-run     # preview; changes nothing
fettle remote server1 update           # just update (asks before upgrading)
fettle remote server1 update --yes     # unattended update (no prompts)
fettle remote server1 orphans kernels  # destructive actions run only when named
fettle remote --ssh-arg=-oConnectTimeout=5 server1 -a
```

- **Safe by default.** `fettle remote <host>` (or `-a`) runs only `clean update
  firmware`. Destructive/interactive actions — **orphan** and **kernel** removal —
  run **only when you name them explicitly**.
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
profile (`inxi`), has Claude research the distro's forums (Arch/Manjaro/Ubuntu/
Reddit) for known issues, and returns a clean, cited verdict with concrete
before/after steps. It is **report-only** — it never touches your system; you run
`fettle -u` yourself once you're satisfied.

```sh
export ANTHROPIC_API_KEY=sk-ant-…
fettle upgrade-check                 # verdict + steps -> ~/upgrade-check.txt
fettle upgrade-check --effort high   # deeper analysis for a big/risky upgrade
fettle upgrade-check --no-web        # skip forum search (faster, cheaper)
```

- **API key** (first found wins): `ANTHROPIC_API_KEY` env → `ai_api_key` in the
  config (keep it `chmod 600` — fettle refuses a world-readable config). No key →
  it just prints the pending-package list. `--print-config` **never** prints the
  key in full — only a `sk-ant-…1234` hint and its source.
- **Privacy:** hardware **serials, MAC addresses, and UUIDs are stripped** from the
  inxi output before anything is sent; only the redacted profile + package list
  reach the API.
- **Grounded, not guessed:** the model is given the real package list and told to
  cite a forum source for every claim (and to call the upgrade routine when it
  finds nothing). fettle then **drops any flagged package that isn't actually
  upgrading** and any source outside the trusted forums — so the report can't warn
  you about things that aren't in your update.
- **Cost & controls:** one request per run — `claude-sonnet-5` at `effort=medium`,
  forum searches capped at `ai_max_web_searches` (default 5) — roughly
  **$0.10–0.30 per check**; the exact token + search count prints at the end. Tune
  via config (`ai_model`, `ai_effort`, `ai_max_web_searches`) or `--model` /
  `--effort`.

Pure stdlib, like everything else — the API is called over `urllib`, no
`anthropic` SDK to install (which also means no `pip`/venv friction on Arch).

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

fettle elevates **lazily and by itself** — you never need to type `sudo fettle`.

- **Maintenance actions** re-exec under `sudo` only when a selected action will
  actually change the system. Read-only work — `pkg-audit`, `aur-audit` (`-A`),
  `aur-ioc-scan` (`-S`), `config-drift` (`-p`) — runs unprivileged and never
  prompts. `--dry-run` never elevates.
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

## License

[MIT](LICENSE).
