# Architecture and contributor contracts

Current for 1.21.0. The CLI uses Python 3.11+ and the standard library. Optional
NiceGUI/FastAPI imports stay under `fettle/web/`; importing the CLI or building a
remote zipapp must not require the web extra. Development and build environments
use [reviewed constraints](dependencies.md).

## Dispatch and backends

The launcher reaches `cli.main`, which manages run recording and exit status.
`cli._main` routes standalone subcommands before the action parser. `SUBCOMMANDS`
feeds completion; action words and flags select a pipeline in `actions.run`.
Distro detection reads `/etc/os-release` and its `ID_LIKE` chain, selecting the
Arch, Debian or RHEL backend. Universal audits do not depend on a package manager.

A backend advertises supported actions. Adding a pipeline action requires updating
CLI action metadata/help, `actions.HANDLERS`, `actions.TITLES`, and backend support
(or `UNIVERSAL_ACTIONS`). Registry tests guard these copies. Also review default
ordering, the everything set, mutation flags and per-backend privilege exceptions.
Prefer consolidation tied to an observed defect; broader registry redesign is deferred.

`Context` carries output, config, invoking identity, dry-run policy and a filesystem
root injected by tests. `command.run` owns subprocess invocation and dropping to the
invoking user's session for per-user stores. `Context.execute` gates mutations and
records unsuccessful commands. The dispatcher consumes backend `Result`s, including
`failure_kind`, without duplicating failures already reported by the backend.
An empty or failed package-manager response is never sufficient proof of no updates.

## Output and privilege

`Output.current_action` tags each summary line. Each pipeline action contributes a
digest even when unsupported or empty. Preserve three distinct failure categories:

| Category | Meaning | Individual action | Everything sweep |
| --- | --- | --- | --- |
| `FAILED` | operational failure | nonzero | nonzero |
| `BLIND` | check could not look | nonzero | reported, no failure solely for this |
| `FOUND` | check ran and found something | nonzero | reported, no failure solely for this |

Intentional `summary_warn` behavior, including declining a prompt and selected
degraded advisory outcomes, remains unchanged. `not_checked` feeds the coverage
block. A new path must report both its outcome and what it failed to inspect.

Read-only and rootless are separate questions. `READ_ONLY_ACTIONS`, explicit root
exception sets, and backend `extra_no_root` determine lazy elevation. Audits may
need root to see other processes or system files; per-user packages must still be
queried as the invoking user. Use `util.invoking_user_home`, not root's home under sudo.
Compromise checks report anomalies and preserve evidence; they never offer remediation.

## Audit families

| Subsystem | Contract | Registry |
| --- | --- | --- |
| Package supply chain | `SourceProvider`: presence, coverage, examined count, normalized findings | backend `supply_chain_sources()` |
| System hardening | `AxisResult`: findings, blindness and not-applicable channels | nine `AXIS_NAMES` plus the binary axis |
| System supply chain | checks operate through an injectable `Scan` | `secure.audit.CATEGORIES` |
| Security advisories | distro providers and OSV language inventories; SQLite cache | `advisories/check.py` |
| Compromise indicators | groups report anomalies, startup inventory and drift | `compromise/audit.py` |
| AUR build review | bounded static token/header inspection; no execution | one engine in `aur/buildscan.py`, three callers |

Use the existing Critical/High/Medium/Low/Info severity scale. Keep known-malware
IOCs distinct from structural review points. Advisory inventories invalidate language
cache results when installed versions change; incomplete OSV pages/records do not
replace a good cache or receive a new successful-refresh timestamp. Stored coverage
is explicit. Multi-branch fixed-version interpretation remains [open](issues.md).

## Configuration and persistence

Config precedence is defaults, TOML, then CLI. Unsafe ownership/mode or malformed
TOML falls back to defaults with a warning. Valid TOML is validated per known key:
valid sibling settings survive, invalid values use defaults, and warnings identify
keys without printing their values. Unknown nested keys remain compatible passthroughs.
Keep `Config` field guidance and [the example](../fettle.toml.example) aligned.

`reports.py` owns timestamped text/JSON pairs under `<base>/reports/<host>/`; run
transcripts use `<base>/logs/<host>/`. Default base is the invoking user's `~/.fettle`.
Writers use private atomic replacements and per-host file locks. Numeric suffixes
identify same-second collisions; retention and dashboard selection must preserve that
ordering. Text-only historical reports remain readable, absent old log exit codes
mean unknown, and malformed known payload containers render as unknown coverage.
Run logging uses a PTY for complete interactive subprocess output and a lightweight
tee for noninteractive Python output. Review its re-exec guards before changing it.

Startup baselines validate entries, replace atomically, preserve invoking ownership,
and warn when refresh fails. Avoid following attacker-controlled symlink destinations
when writing elevated output. Test concurrent writers and cancellation where changed.

## Remote, web and packaging

Remote execution ships a standard-library zipapp over SSH, selects an available
Python 3.11+ interpreter, preserves the command's exit status, removes the temporary
archive and fetches reports back. Remote config belongs to the remote invoking user.
Custom remote report-directory discovery is still [open](issues.md).

The web UI remains experimental. Its ASGI guard protects HTTP and WebSockets with
loopback Host and same-origin checks. Browser WebSockets require Origin. A global
runner lock prevents overlapping actions across pages; cancellation terminates the
child process group. Noninteractive stdin closes, submitted passwords clear, and
buttons describe privileged metadata refresh correctly. Focus browser QA on harmless
fake runners, alongside HTTP/WS regression tests; do not use workstation mutation.

All distro packages call `packaging/install.sh`. A shared wrapper selects a supported
interpreter without tying the install to a Python minor-version directory. Nuitka
builds explicitly include the current hardening registry and embed a remote zipapp.
Every native artifact runs a smoke test before delivery. CI covers Python 3.11–3.14
and optional web tests; tagging triggers a draft release only. Repair uploads require
a confirmed draft. This maintenance work creates no tag or public release.

Run focused behavior regressions, Ruff with `E4,E7,E9,F`, and appropriate broader
checks. Use disposable containers/VMs for mutations. Record genuine prerequisite,
hardware and environment gaps in [verification](maintenance-verification.md), and
keep historical QA evidence and permanent case IDs intact. Local memories and lab
configuration stay untracked; reusable guidance belongs here.
