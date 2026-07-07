# fettle

> *in fine fettle* — in good working order.

A cross-distribution Linux system-maintenance and supply-chain tool: update,
clean, prune orphans, check for rebuilds/restarts, review config-file drift,
apply firmware updates, manage kernels, audit third-party package sources, and
run a full firmware/boot-chain security scan (`sys-audit`) — with the same
command surface on every supported distro.

Two supply-chain feature families, kept distinct:
**Package Supply Chain** (`pkg-audit`) — where software came from and whether it's
tampered (packages, repos, publishers, integrity) across AUR/APT/Flatpak/Snap; and
**System Supply Chain** (`sys-audit`) — the machine's firmware/boot/hardware posture.

`fettle` is the Python successor to the Arch/Manjaro `update.sh` (from
[`linux_hacks`](https://github.com/pasadoorian/linux_hacks)), rebuilt around a
pluggable per-distro backend so new distributions are a single new class.

**Status:** the Arch/Manjaro backend is feature-complete and at parity with
`update.sh` (update, clean, orphans, rebuilds, python-rebuild, config drift,
firmware, kernels, and the AUR package supply-chain audit), including the
install-time yay hook. The Debian backend and the `sys-audit` security scanner
are in progress.

## Supported distros

| Distro family | Backend | Package tooling | State |
|---|---|---|---|
| Arch / Manjaro | `arch` | pacman + yay/pamac + AUR | ready |
| Debian / Ubuntu | `debian` | apt + flatpak + snap | in progress |

## Installation

`fettle` is pure standard library, so there is **nothing to pip-install** — the
launcher runs the checked-out repo in place. You need Python 3.11+ and whatever
tooling the actions you use require (on Arch: `pacman`, optionally `yay`/`pamac`,
`rebuild-detector`, `pacman-contrib`, `fwupd`; on Manjaro also `mhwd-kernel`).

```sh
git clone https://github.com/pasadoorian/fettle.git ~/src/fettle
ln -s ~/src/fettle/bin/fettle ~/.local/bin/fettle   # ensure ~/.local/bin is on PATH
fettle --help
```

`bin/fettle` puts the repo on `PYTHONPATH` and runs `python3 -m fettle`, so a
`git pull` is all it takes to update. To drop it in for the old updater:

```sh
ln -sf ~/src/fettle/bin/fettle ~/update.sh
```

### yay install-time supply-chain hook (Arch/Manjaro, optional)

An advisory, warn-only AUR precheck that fires at install time (orphaned /
out-of-date / compromised name / malicious maintainer), on top of yay's build-file
review:

```sh
cp ~/src/fettle/contrib/yay-init.lua ~/.config/yay/init.lua
```

## Usage

```sh
fettle                   # run the default maintenance set
fettle -c -u             # clean + update (short flags)
fettle update            # same as -u (subcommand form)
fettle -A                # AUR audit: per-package health table -> ~/aur-audit.txt
fettle aur-ioc-scan      # -S: scan installed AUR pkgs for IoCs -> ~/aur-ioc-scan.txt
fettle --all --dry-run   # show everything that would run; change nothing
fettle --print-config    # show the effective configuration
```

The two AUR supply-chain commands are distinct: **`-A` / `aur-audit`** is a
provenance/health census (age, votes, out-of-date, orphan, recently-changed,
maintainer-change), while **`-S` / `aur-ioc-scan`** checks installed packages
against malware indicators (known-bad package names, malicious maintainer
accounts, malicious JS-dependency traces). `pkg-audit` is the cross-distro
normalized-findings audit that the Debian/Flatpak/Snap backends will feed into.

Config lives at `~/.config/fettle/config.toml` (see `fettle.toml.example`);
precedence is built-in defaults < config file < CLI flags.

## Design at a glance

- **Pure Python standard library** — zero third-party dependencies (this runs as
  root; the trusted surface stays minimal).
- **Python 3.11+**.
- **TOML** config (`tomllib`), precedence: built-in defaults < config file < CLI.
- **Hybrid CLI** — the familiar short flags (`fettle -c -u`) *and* subcommands
  (`fettle update`).
- **Hardcoded backend registry** keyed on `/etc/os-release` — add a distro by
  adding one `PackageBackend` subclass and one registry line.

## License

[MIT](LICENSE).
