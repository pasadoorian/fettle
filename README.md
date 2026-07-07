# fettle

> *in fine fettle* — in good working order.

A cross-distribution Linux system-maintenance and supply-chain tool: update,
clean, prune orphans, check for rebuilds/restarts, review config-file drift,
apply firmware updates, manage kernels, audit third-party package sources, and
run a full firmware/boot-chain security scan (`secure-check`) — with the same
command surface on every supported distro.

`fettle` is the Python successor to the Arch/Manjaro `update.sh` (from
[`linux_hacks`](https://github.com/pasadoorian/linux_hacks)), rebuilt around a
pluggable per-distro backend so new distributions are a single new class.

**Status:** design / planning. See [PLAN.md](PLAN.md) for the full conversion
plan, architecture, and milestones.

## Supported distros (planned)

| Distro family | Backend | Package tooling |
|---|---|---|
| Arch / Manjaro | `arch` | pacman + yay/pamac + AUR |
| Debian / Ubuntu | `debian` | apt + flatpak + snap |

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

TBD (public repo — see PLAN.md open items).
