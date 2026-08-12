<p align="center">
  <img src="assets/fettle-logo-800w.png" alt="fettle" width="440">
</p>

> # **This is 1.0.0 — the first official and tested release of fettle.**
>
> The web interface (`fettle web`) is still experimental.

> *in fine fettle* — in good working order.

**fettle** is a cross-distribution Linux system-maintenance and supply-chain tool.
One command surface keeps your machine updated and clean, audits where your
software came from and whether it has been tampered with, checks how the system is
hardened, and scans the firmware / boot chain for security posture — on
Arch/Manjaro, Debian/Ubuntu and the RHEL family alike.

It is the Python successor to the Arch/Manjaro `update.sh`, `aur-precheck.sh`, and
`supply_chain_check.sh` scripts (from
[`linux_hacks`](https://github.com/pasadoorian/linux_hacks)), rebuilt around a
pluggable per-distro backend so a new distribution is a single new class, and with
real unit-test coverage the bash originals never had.

- **Pure Python standard library** — zero third-party runtime dependencies.
- **Python 3.11+** (uses `tomllib`).
- Nothing to `pip install`: install a package, or run the repo in place.

**📖 The full manual is in the [wiki](https://github.com/pasadoorian/fettle/wiki).**
This page is what fettle is, whether it runs on your machine, and how to install it.

---

## Contents

- [What it does](#what-it-does)
- [Supported distributions](#supported-distributions)
  - [What works where](#what-works-where)
- [Requirements](#requirements)
- [Installation](#installation)
  - [From a checkout, to follow `main`](#from-a-checkout-to-follow-main)
  - [Optional: the zipapp](#optional-the-zipapp)
  - [Optional: the prebuilt binary](#optional-the-prebuilt-binary)
  - [Optional: bash completion](#optional-bash-completion)
  - [Optional: yay install-time supply-chain hook (Arch/Manjaro)](#optional-yay-install-time-supply-chain-hook-archmanjaro)
- [Quick start](#quick-start)
- [Documentation](#documentation)
- [fettle vs. topgrade](#fettle-vs-topgrade)
- [Changelog](#changelog)
- [License](#license)

---

## What it does

fettle has six feature families.

1. **Maintenance** — update packages, clean caches, prune orphans, check for
   rebuilds/service-restarts, review config-file drift, report whether automatic
   updates are enabled, apply firmware updates, and manage kernels.
2. **Package Supply Chain** — *where software came from and whether it's tampered*:
   third-party repos/PPAs, publishers, staleness, sandbox permissions, and (for
   the AUR) live malware-IOC feeds. Exposed as `pkg-audit`, plus `pkg-integrity`
   (do the installed *files* still match the package?), the Arch-specific
   `aur-audit`, and the install-time yay hook (`aur-precheck`).
3. **System Supply Chain** — *the machine's firmware/boot/hardware posture*:
   Secure Boot, BIOS/UEFI, TPM, Intel ME, CPU microcode, hardware and storage
   firmware. Exposed as `sys-audit`, runnable locally or over SSH.
4. **System Hardening** — *is this machine configured safely?* Seven independent
   axes: were the installed binaries built with the distro's hardening flags, can a
   local user tamper with shared directories, how much of the system can each
   running service reach, are the kernel's runtime protections switched on, what is
   sshd *actually* configured to do, is a firewall both active and filtering, and are
   any TLS certificates expired. Exposed as `hardening-audit` (`-H`).
5. **Security advisories** — *is what you have installed known-vulnerable?*
   Per-package CVEs from your distro's own tracker, including the ones you're
   vulnerable to with **no fix released yet**, plus the Python/Node/Rust packages
   your distro doesn't manage, via OSV. Exposed as `advisory-check`.
6. **Compromise indicators** — *is something already here?* What starts at boot that
   no package installed (units, timers, cron, `at`), the loader and kernel
   (`/etc/ld.so.preload`, unsigned modules, kernel taint nothing explains, the eBPF
   surface, processes hidden from `/proc`), what is running (executed from memory,
   deleted-but-running, listening sockets nothing vouches for) and the boot chain.
   Exposed as `compromise-check` (`-M`). **It reports anomalies to investigate and
   never a fix** — if a finding is real, running the fix destroys the evidence.

The last two are the pair most easily conflated, and they are separate actions because
they have different answers: hardening asks whether the machine is **configured** safely,
compromise asks whether something is **already here**. One ends in a command to run;
the other ends in something to look at before you touch anything.

Three of the names are easy to confuse, so they are kept deliberately distinct in
code, docs, and CLI:
"where did this software come from / is it tampered?" → **Package**
(`pkg-audit`); "is the machine's firmware/boot sound?" → **System** (`sys-audit`);
"is the machine configured safely?" → **Hardening** (`hardening-audit`).

**All six run three ways.** Locally; over SSH against one host or a named group,
with nothing installed on the far side — fettle ships itself (`fettle remote`); and
into a report — every run saves one under `~/.fettle/` with a JSON sibling, and
`fettle report` builds a multi-host HTML dashboard with a per-host verdict.
`upgrade-check` (`-U`, experimental) adds an AI second opinion on a pending upgrade
set, local or remote.

One invariant runs through all of it: **a check that cannot look never renders like
a clean result.** Every audit distinguishes "found nothing wrong" from "could not
tell", and says which it means.

## Supported distributions

| Family | Backend | Package tooling | Detected `ID` / `ID_LIKE` |
|---|---|---|---|
| Arch / Manjaro | `arch` | pacman + yay/pamac + AUR | `arch`, `manjaro`, `endeavouros`, … |
| Debian / Ubuntu | `debian` | apt/nala + flatpak + snap | `debian`, `ubuntu`, `linuxmint`, `pop`, … |
| RHEL family | `rhel` | dnf + rpm + podman | `rhel`, `centos`, `rocky`, `almalinux`, `ol` |

**RHEL support is complete**, at parity with Debian: every action except the three that
are Arch-only by nature (`aur-audit`, `aur-precheck`, and `python-rebuild-check`, which dnf
handles itself). Fedora is deliberately not claimed as a *distro*: it shares dnf, but its
advisories come from Bodhi as `FEDORA-*` rather than Red Hat's `RHSA-*` (`--distro rhel`
still works there, and is how the dnf5 code path is tested).

### What works where

● supported · — not applicable to this family · ✔︎ runs by default when you type plain
`fettle`. Per-distro *behaviour* is in [Maintenance actions](https://github.com/pasadoorian/fettle/wiki/Maintenance-actions); this is
the at-a-glance "will it run on my box" view.

| | Flag | Arch | Debian | RHEL | Default |
|---|---|:--:|:--:|:--:|:--:|
| Update everything | `-u` | ● | ● | ● | ✔︎ |
| Refresh metadata + report upgradable | `-O` | ● | ● | ● | |
| Clean package caches | `-c` | ● | ● | ● | ✔︎ |
| Orphaned / unused packages | `-o` | ● | ● | ● | ✔︎ |
| Pending reboot, rebuilds & restarts | `-r` | ● | ● | ● | ✔︎ |
| Pending config-file merges | `-d` | ● | ● | ● | ✔︎ |
| Automatic-update posture | `-x` | ● | ● | ● | ✔︎ |
| Firmware updates | `-f` | ● | ● | ● | ✔︎ |
| Kernel management | `-k` | ● | ● | ●¹ | |
| Supply-chain audit | `-P` | ● | ● | ● | ✔︎ |
| Binary hardening audit | `-H` | ● | ● | ●² | |
| Compromise indicators | `-M` | ● | ● | ● | ³ |
| Container image updates | `-C` | ● | ● | ● | |
| Python rebuild check | `-y` | ● | — | — | ✔︎ |
| AUR health census | `-A` | ● | — | — | |
| AUR compromise (IoC) scan | `-P` | ● | — | — | ✔︎ |
| | | **16/16** | **13/16** | **13/16** | |

The three gaps are the same on Debian and RHEL and are Arch-only by nature — there is no
AUR elsewhere, and both apt and dnf handle Python interpreter transitions themselves. So
Debian and RHEL are *complete*, not partial.

¹ Reported, never removed: dnf enforces `installonly_limit` and prunes old kernels itself.
Arch and Debian do offer removal, because pacman and apt do not.
³ Not in the default set — it needs root, and a compromise finding is not something
to meet in a routine maintenance run. It **is** swept by `--everything`, where it runs
last: an update removes a vulnerable package and does not remove an implant.
² Needs `checksec`, which is **not packaged for RHEL 10 — EPEL included** — so in practice
this cannot run there yet. The code and tests are in place for when it is. Both checksec
generations are handled: 3.x (Arch) and 2.x (Fedora, Debian, Ubuntu), which share no
command line.

**Distro-independent features** work the same everywhere: the `sys-audit` firmware/boot
scan (`-S` — every one of its checks is distro-neutral), `fettle remote` over ssh, the
AI upgrade checker (`-U`), the HTML report and the web UI. `advisory-check` has native CVE
feeds for **Arch, Debian, Ubuntu and RHEL**, plus language dependencies via OSV. And
`pkg-audit` covers the **same seven ecosystems on every distro** — the native one
(AUR / apt / dnf) plus flatpak, snap, containers, GNOME extensions, VS Code extensions and
GitHub CLI extensions.

**Ubuntu-specific:** on a host not attached to **Ubuntu Pro**, `apt` cannot see the
`esm-infra` / `esm-apps` pockets, so the number of available security updates it reports is
smaller than reality. fettle reads `pro security-status` and says so — both in the upgrade
preview when updates are being withheld, and in `-x`, which names how many installed
packages (typically Universe/Multiverse) receive no security updates at all without a
subscription.

Three RHEL-specific things worth knowing:

- **`-u --dry-run` shows upgrades only.** dnf has no rootless equivalent of
  `apt-get -s` — `dnf upgrade --assumeno` resolves the complete transaction but refuses
  to run without root. The preview says so rather than passing a partial answer off as
  a complete one; add **`--full-preview`** to elevate and see new dependencies and
  removals too.
- **An upgrade from a repository with `gpgcheck=0` asks one extra time.** Those packages
  are installed without verifying their signature. `--yes` proceeds, loudly.
- **`-o` never offers a kernel for removal.** dnf's own `autoremove` has been known to
  propose removing kernels when the `dnf mark` reason data is incomplete, and removing a
  running one leaves an unbootable machine. Installonly packages are held back and named,
  and if the query that identifies them fails, *nothing* is offered.

On an **image-based** host (rpm-ostree, Fedora Silverblue, RHEL Image Mode / bootc)
fettle refuses to dnf-upgrade at all and points at `bootc upgrade` / `rpm-ostree
upgrade`, because a dnf transaction there does not survive a reboot.

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
| orphans | (built-in) | `apt-show-versions`; `deborphan` if present, else dpkg reverse-deps (built-in) |
| firmware | `fwupd` | `fwupd` |
| kernels | `mhwd-kernel` (Manjaro) | (built-in `dpkg`) |
| flatpak / snap | — | `flatpak`, `snapd` |
| hardening audit (`-H`) | `checksec` | `checksec` |
| compromise indicators (`-M`) | `bpftool` (optional) | `bpftool` (optional) |

(RHEL family: `checksec` too — `dnf install checksec`.)

Every tool above is optional and its check is skipped with a note when absent.
The one you likely need to install is **`checksec`** for the hardening audit:

```sh
sudo pacman -S checksec      # Arch / Manjaro
sudo apt install checksec    # Debian / Ubuntu
```

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

Packages for each release are on the
[releases page](https://github.com/pasadoorian/fettle/releases/latest). Every one is
built and then installed and run in a clean container of its own distro before it is
published.

```sh
sudo apt install ./fettle_*_all.deb              # Debian, Ubuntu
sudo dnf install ./fettle-*.noarch.rpm           # RHEL, Rocky, AlmaLinux, Fedora
sudo pacman -U fettle-*-any.pkg.tar.zst          # Arch, Manjaro
```

They depend on nothing but a python 3.11+ interpreter, and pull one in on the
distributions whose default `python3` is older (RHEL 9, Ubuntu 22.04).

Check what you downloaded against the release's `SHA256SUMS`:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

No package for your system? The **zipapp** runs anywhere there is a python 3.11+, and
the **prebuilt binary** needs no python at all — both are on the same page, and both are
described below.

### From a checkout, to follow `main`

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

### Optional: the zipapp

One file that runs under any python 3.11+, with nothing to install — the fallback for
a system with no package and a glibc too old for the binary. Attached to each release
as `fettle-<version>-zipapp.tar.gz` / `.zip`.

```sh
tar -xzf fettle-*-zipapp.tar.gz && cd fettle-*/
./fettle --version                                  # runs in place
sudo install -m 755 fettle.pyz fettle /usr/local/bin/    # or put it on PATH
```

`fettle` is a small launcher that resolves `fettle.pyz` **beside itself** and picks a
suitable interpreter, so install the pair into the same directory. It exists because
`python3` is not reliably 3.11+ — it is 3.9 on RHEL 9 and 3.10 on Ubuntu 22.04, and
running fettle under either fails somewhere further in rather than at once.

### Optional: the prebuilt binary

A single self-contained executable — no python needed, nothing to install. Attached to
each release as `fettle-<version>-linux-x86_64.tar.gz` / `.zip`.

```sh
tar -xzf fettle-*-linux-x86_64.tar.gz && cd fettle-*/
sudo install -m 755 fettle /usr/local/bin/fettle
```

It needs **glibc 2.38 or newer**, so it runs on Ubuntu 24.04, Debian 13, Fedora 40+ and
Arch, but **not** on Ubuntu 22.04, Debian 12 or RHEL/Rocky/AlmaLinux 9. On those, use
the distro package or the zipapp — both are on the same release page and both work
everywhere. The limit comes from the python runtime compiled into the binary, not from
fettle.

`fettle --version` prints `(binary)` for this build, so a bug report says which artifact
it came from.

### Optional: bash completion

```sh
source ~/src/fettle/contrib/fettle.bash                        # or, system-wide:
sudo ln -s ~/src/fettle/contrib/fettle.bash /usr/share/bash-completion/completions/fettle
```

Completes every flag and action at the top level, and each subcommand's own options
inside it — so `fettle report <TAB>` offers `--open` and `--backfill-json`, and does
*not* offer `--dry-run`, because `fettle report --dry-run` is not a thing.
`fettle sys-audit <TAB>` also offers the nine check categories and drops the ones you
have already typed. `fettle -S <TAB>` completes as `sys-audit`, since that is what it
runs.

The script is about six lines and **knows nothing about fettle's options** — it asks
`fettle` itself, so it cannot fall out of step with the CLI. Each tab press costs
roughly 70 ms.

Two things it deliberately does not do. It completes **names, not values**: no paths for
`--config`, hosts for `remote`, or package names for `aur-precheck` (sys-audit's
categories are the exception, being a fixed set). And it binds to the `fettle` command,
so `python -m fettle` gets nothing — bash completes on the command name, and there the
command is `python`.

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
fettle -A                  # AUR health audit  -> ~/.fettle/reports/
fettle -P                  # package supply-chain audit -> ~/.fettle/reports/
fettle -H                  # system hardening audit -> ~/.fettle/reports/
fettle -M                  # compromise indicators: is something already here?
fettle -S                  # full security scan (sys-audit --all; self-elevates)
fettle -U                  # AI: is this upgrade safe? [experimental] (needs API key)
fettle report              # multi-host HTML dashboard from the saved reports
fettle remote host -u      # any action on another box over ssh (nothing to install there)
```

## Documentation

Everything else — every action, every flag, every config key, and the reasoning
behind the defaults — is in the
**[wiki](https://github.com/pasadoorian/fettle/wiki)**.

| Page | What's in it |
|---|---|
| [Maintenance actions](https://github.com/pasadoorian/fettle/wiki/Maintenance-actions) | Reading fettle's output, the full action table per distro family, what each action actually runs, `--everything`, and previewing an upgrade |
| [Package supply-chain](https://github.com/pasadoorian/fettle/wiki/Package-supply-chain) | `pkg-audit`, `pkg-integrity`, `aur-audit`, `aur-precheck` — provenance, IoC feeds, and the pre-upgrade gate |
| [System hardening audit](https://github.com/pasadoorian/fettle/wiki/System-hardening-audit) | `-H` and its seven axes, what each one can and can't see, and how to tune or disable them |
| [System supply-chain](https://github.com/pasadoorian/fettle/wiki/System-supply-chain) | `sys-audit` — Secure Boot, TPM, microcode, SPI/BIOS, storage firmware; local and remote |
| [Security advisories](https://github.com/pasadoorian/fettle/wiki/Security-advisories) | `advisory-check` — distro CVE feeds, OSV for language dependencies, and the warn-gate |
| [Remote maintenance](https://github.com/pasadoorian/fettle/wiki/Remote-maintenance) | `fettle remote`, host groups, and how fettle gets itself onto a host that doesn't have it |
| [Configuration & reporting](https://github.com/pasadoorian/fettle/wiki/Configuration-and-reporting) | The full `config.toml`, reports and run logs, `fettle report`, and the experimental web UI |
| [AI upgrade check](https://github.com/pasadoorian/fettle/wiki/AI-upgrade-check) | `upgrade-check` — what it sends, what it costs, and why it's experimental |
| [Reference](https://github.com/pasadoorian/fettle/wiki/Reference) | Common options, exit codes, how elevation works, architecture, and development |

## fettle vs. topgrade

[topgrade](https://github.com/topgrade-rs/topgrade) is the closest widely-used
tool, and fettle's design was informed by it — so here's an honest comparison.
**They aim at different problems.** topgrade is a broad, cross-platform *upgrade
orchestrator*: it detects the tools you use and runs all of them. fettle is a
focused Linux *maintenance **and** supply-chain-security* tool with a small,
curated command set.

| | topgrade | fettle |
|---|---|---|
| Platforms | Linux, macOS, Windows, BSD | Arch/Manjaro, Debian/Ubuntu and RHEL families only |
| Integrations | ~60+ across many ecosystems | curated: pacman/apt/dnf (+ yay/pamac/nala), flatpak, snap, containers, fwupd, kernels, AUR |
| Language toolchains (pip/npm/cargo/gem…), editors, dotfiles, git repos | ✅ updates them | ❌ deliberately out of scope |
| Tool selection | auto-detects installed tools | explicit per-distro allowlist — config tunes behaviour, never *discovers* commands |
| Self-update | ✅ | ❌ by design (your package manager owns fettle) |
| Skip / run-only specific steps | ✅ | ✅ (`--skip` / `--only`) |
| Dry-run | ✅ | ✅ — plus a full **resolved transaction preview** (upgrades + new deps + removals) |
| Asks before upgrading | mostly unattended | ✅ by default (`--yes` for unattended) |
| Remote over SSH | ✅ run topgrade on remote hosts | ✅ any action over ssh, **plus** remote security scan and remote AI upgrade-check |
| Config | TOML | one flat TOML + a safety gate (refuses world-writable / wrong-owner) |
| Firmware updates (fwupd) | ✅ | ✅ |
| Auto-update posture report (is the system set to auto-update itself?) | ❌ (runs upgrades; doesn't report update config) | ✅ `auto-updates` (`-x`) |
| End-of-run summary | ✅ | ✅ (+ next steps) |
| Runtime | single Rust binary | pure Python standard library (any `python3`; no `pip`) |
| Maturity / ecosystem | established, widely packaged, large community | 1.0.0, three distro families (Arch, Debian, RHEL) |
| **Package provenance / tamper audit** (AUR/APT/Flatpak/Snap) | ❌ | ✅ `pkg-audit` |
| **System hardening audit** (build flags, filesystem, services, kernel, sshd, firewall, TLS certs) | ❌ | ✅ `hardening-audit` (`-H`) |
| **Firmware / boot security scan** (Secure Boot, TPM, microcode, chipsec…) | ❌ | ✅ `sys-audit` |
| **AUR IoC scan + install-time pre-flight** | ❌ | ✅ `pkg-audit`, `aur-precheck` |
| **Package-file integrity verification** | ❌ | ✅ via `pkg-integrity` (paccheck / debsums / rpm -Va) |
| **Security advisories / CVE tracking** (incl. *vulnerable, no fix released yet*) | ❌ | ✅ `advisory-check` (distro feeds + OSV for Python/Node/Rust) |
| **AI pre-upgrade advisor** | ❌ | ✅ `upgrade-check` (local **and** remote) |

**Which should you use?**

- **topgrade** if you want one command to update *everything, everywhere* — system
  packages, language toolchains, editors, containers, dotfiles — with a huge,
  battle-tested integration set across every major OS.
- **fettle** if you're on Arch, Debian or RHEL and want maintenance **with a security
  lens**: know where your packages came from and whether they've been tampered
  with, scan your firmware/boot posture, and get an AI second opinion before a big
  upgrade — through a small, curated, auditable command set with no runtime deps.

They're **complementary** — it's reasonable to run topgrade for breadth and fettle
for the Linux provenance / security / firmware angle. Several of fettle's
deliberate *non-goals* (no self-update, no auto-discovery of commands, no
cascading config) are lessons taken from topgrade's rough edges — not a knock on a
tool that does far more, on far more platforms, than fettle aims to.

<sub>topgrade details summarized from its README and `config.example.toml`, July 2026.</sub>

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full, versioned history.

## License

[MIT](LICENSE).
