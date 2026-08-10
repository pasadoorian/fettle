# Packaging

Three distro packages, all built from one staged layout so they cannot drift apart.

```
packaging/
  install.sh          stages the installed tree into $DESTDIR — the single source of layout
  version.sh          prints the version from pyproject.toml — the single source of version
  check-tag.sh        the release guard: does the git tag match that version?
  wrapper.sh.in       the `fettle` launcher template — the single source of the
                      interpreter search, used by the packages AND the zipapp archive
  deb/build.sh        → dist/fettle_<version>_all.deb
  rpm/build.sh        → dist/fettle-<version>-1.noarch.rpm      (+ fettle.spec)
  arch/build.sh       → dist/fettle-<version>-1-any.pkg.tar.zst (+ PKGBUILD)
  zipapp/pyz.sh       → just the .pyz — shared with the binary, which embeds one
  zipapp/build.sh     → dist/fettle.pyz
                        dist/…-zipapp.tar.gz  and  dist/…-zipapp.zip
  binary/build.sh     → dist/fettle  (Nuitka, single x86_64 executable)
```


The zipapp is the artifact that runs **everywhere** — any distro, any architecture, as
long as there is a python 3.11+. The Nuitka binary that comes later is built against one
glibc and therefore does not; this is what covers the machines it misses. It is built by
fettle's own `remote.build_zipapp`, the same function `fettle remote` uses to ship itself
to a host, so the file people download and the one that lands on a remote machine cannot
become different things.

The `-zipapp` suffix is not decoration: GitHub attaches its own *Source code (zip)* and
*(tar.gz)* to every tag, named `fettle-<version>.zip` and `.tar.gz`. Without the suffix
these would collide on the release page.

Every script writes to `dist/`, which is gitignored, and takes an optional output
directory as its first argument.

## Releasing

Pushing a version tag is the decision to release — nothing else triggers
`.github/workflows/release.yml`, so a normal merge to main cannot cut one by accident.
That matters here: fettle bumps its version on nearly every commit, so a
merge-triggered release would have produced well over a hundred of them.

```bash
packaging/check-tag.sh "v$(packaging/version.sh)"   # pre-flight, always passes
git tag v1.0.0 && git push --tags
```

The workflow runs the guard first, then the suite on 3.11/3.12/3.13, then builds each
package **and installs it in a clean container of its own distro**, and finally creates
a **draft** release. Publishing is a human step, so a bad build can be deleted before
anyone sees it.

Two things are generated at publish time rather than written by hand:

**`SHA256SUMS`**, over every attached file, verifiable with
`sha256sum -c SHA256SUMS --ignore-missing`. It is written outside the staging directory
and moved in, because `sha256sum * > SHA256SUMS` in the same directory is a classic way
to checksum an empty file that is about to be your checksums.

**The release notes**, from `CHANGELOG.md`'s section for that version
(`packaging/release-notes.sh`). The entry is already written by hand for every release
with the reasoning in it, so generating the page from it means one account of each
change rather than two that can disagree. It **fails** if the version has no section —
the fallback would be GitHub's auto-generated commit list, which for a release like
1.0.0 is a wall of `packaging P4: …` lines and says nothing a user wants. A short table
explaining what each artifact is gets appended, since that part is identical every time.

**The guard is `packaging/check-tag.sh`,** and it exists because a release tagged
`v1.0.0` whose packages call themselves `0.120.0` installs, runs, and lies about what it
is — every bug report afterwards then names a version that was never built. It is a
script rather than a few lines of YAML so `tests/test_packaging.py` can exercise it and
so you can run it before tagging.

## Building locally

```bash
packaging/deb/build.sh                          # needs dpkg-deb
RPMBUILD_FLAGS=--nodeps packaging/rpm/build.sh  # needs rpmbuild
packaging/arch/build.sh                         # needs makepkg, and must NOT be root
```

Two of those need a flag on the "wrong" host, and both for the same reason: `rpmbuild`
and `makepkg` check build dependencies against the **local** package database, and on a
machine of the other family that database is empty — so `python3` cannot be satisfied
even though it is plainly installed. The dependency is still recorded in the built
package; only the build-time check is skipped. CI builds each one in its own container
where the check passes for real.

`makepkg` refuses to run as root, and containers run as root by default, so the Arch CI
job needs an unprivileged build user. It fails with a message that reads like a
permissions bug rather than a policy one, which is worth knowing before you debug it.

## What lands where

```
/usr/lib/fettle/fettle/…                       the package
/usr/bin/fettle                                wrapper putting the above on PYTHONPATH
/usr/share/bash-completion/completions/fettle
/usr/share/doc/fettle/                         README, LICENSE, fettle.toml.example
/usr/share/licenses/fettle/LICENSE             (Arch convention, in addition)
```

**Not a python site-packages directory.** On Arch and the RHEL family that path carries
a python *minor* version (`/usr/lib/python3.13/site-packages`), so an interpreter upgrade
would strand the install — the exact breakage `fettle -y` exists to detect in other
people's packages. Debian's `dist-packages` is version-independent, but two layouts for
two families is worse than one that works everywhere. fettle is a CLI, not a library, so
nothing needs to `import fettle`.

## The compiled binary, and why it needed code changes

`packaging/binary/build.sh` compiles fettle with **Nuitka** into a single ~12 MB
x86_64 binary. Nuitka translates the python to C and compiles it, so the result is a
real native executable rather than an interpreter with an archive attached.

Building it is the easy half. fettle **re-executes itself** twice — to elevate via
`sudo`, and to relaunch under a pty so it can transcribe a run — and both built
`[sys.executable, "-m", "fettle", …]`, which is meaningless when there is no
interpreter and no `fettle` package on disk. `sudo fettle -u`, the single most important
thing the tool does, would have failed.

Three things were measured against a real build rather than assumed, and the first would
have produced a bug nobody could diagnose:

- **`sys.executable` is not the binary.** It is `/tmp/onefile_…/python`, a scratch
  directory Nuitka unpacks itself into and removes on exit. Re-exec'ing it works while
  the parent process lives and fails afterwards. `sys.argv[0]` is the binary, and Nuitka
  resolves it to an absolute path even when invoked by bare name from PATH.
- **Nuitka does not set `sys.frozen`.** It adds `__compiled__` to every compiled module,
  so `util.frozen_binary()` tests for both and a PyInstaller build would also work.
- **`fettle/__main__.py` cannot be the entry point.** It does `from .cli import main`, a
  relative import needing package context, so the binary compiles and then dies at
  startup. The build generates a two-line absolute-import entry instead — the same thing
  `remote.build_zipapp` already does, so the two artifacts start the same way.

**`fettle remote` needs an embedded zipapp.** It ships fettle to a host by building a
`.pyz` from fettle's own `.py` files — which a compiled build does not have, so it failed
with a bare `FileNotFoundError` traceback naming Nuitka's scratch directory and nothing
about the cause. The build now produces a zipapp (`packaging/zipapp/pyz.sh`, shared with
the zipapp artifact so they are the same thing) and embeds it with
`--include-data-files`; `remote.build_zipapp` copies it out instead of staging. About
800 KB on a 13 MB binary. A build made *without* it raises an error naming the missing
flag rather than falling through to the staging path, because that path's exception
points at a temp directory and not at the mistake.

**The axes get a Nuitka include flag each, and a smoke test.** They are loaded by a
computed module name that no compiler can see. Measured rather than assumed:
`--include-package=fettle` already pulls them in, so those flags are *redundant* — a
build made without them was compiled and all six axes were present. They stay as
belt-and-braces, derived from `AXIS_NAMES` so a seventh cannot be forgotten, but they
are not what makes it work.

The check that matters is `packaging/binary/smoke.sh`, which every build runs before its
output becomes an artifact. If an axis is ever lost the binary does **not** crash — the
framework catches the ImportError and reports it as *blind*. Demonstrated by compiling
one with two axes deliberately excluded:

```
  Filesystem: not checked (see below)
  Kernel: not checked (see below)
```

Exit code 0, no error, an audit that looks careful and examined nothing. The smoke test
turns that into a failed build. It also asserts the binary knows it is a binary, that
`fettle remote` can still build its zipapp, and that config parsing works — always by
checking for *positive results* rather than a zero exit.

Verified end to end in a container, as an unprivileged user with passwordless sudo:

```
binary:  sudo /usr/local/bin/fettle -V --config /home/tester/.config/fettle/config.toml
python:  sudo env PYTHONPATH=/tmp/src /usr/sbin/python3 -m fettle -V --config …
```

Both correct for their case, the config pin preserved in both — and the python path
byte-identical to what it always was, which is what says the change is additive.

## The python 3.11 floor, which is the fiddly part

fettle needs python **3.11 or newer**, and `python3` is *not* reliably that:

| distro | `python3` is | fettle needs |
|---|---|---|
| RHEL / Rocky / Alma 9 | **3.9** | `python3.11` or `python3.12` from appstream |
| Ubuntu 22.04 | **3.10** | `python3.11` from universe |
| Debian 12 / 13, Fedora, Arch | 3.11 – 3.14 | already fine |

Two halves, and both are needed — either alone leaves a broken install:

**The dependency** is expressed in each distro's dialect, so the package manager pulls a
suitable interpreter in rather than refusing: `Depends: python3 (>= 3.11) | python3.11 |
…` for deb, the rpm boolean `Requires: (python3 >= 3.11 or python3.11 or …)`, and plain
`python>=3.11` on Arch. A flat `python3 >= 3.11` would refuse to install on the entire
EL9 family and on Ubuntu 22.04 — platforms fettle supports and runs on perfectly well.

**The wrapper** then has to *find* that interpreter, because `python3` still points at
the old one. `/usr/bin/fettle` tries `python3.14 … python3.11` by name first — the name
alone guarantees the version, so nothing has to be started to find out, which keeps the
common path free of an extra process (bash completion runs this on every tab press).
Only if none of those exist does it fall back to `python3` and check it properly. The
version list is an optimisation, not the correctness: a python newer than anything named
there is still found by the fallback.

Verified on real containers, including both platforms that a naive dependency breaks:

| distro | system `python3` | pulled in | wrapper execs |
|---|---|---|---|
| Rocky 9 | 3.9.25 | `python3.12` | `python3.12` |
| Ubuntu 22.04 | 3.10.12 | `python3.11` | `python3.11` |
| Debian 12 | 3.11.2 | — | `python3.11` |
| Arch | 3.14.6 | — | `python3.14` |

## Verifying a build

Building proves the metadata parses. **Installing proves the layout is right, and the
layout is where these go wrong** — so each package is installed into a clean container
of its own distro and actually run:

```bash
podman run --rm -v "$PWD/dist":/d:ro docker.io/library/debian:12 sh -c \
  'apt-get -qq update >/dev/null && apt-get -qq install -y python3 >/dev/null &&
   dpkg -i /d/fettle_*.deb && fettle --version && fettle -H --dry-run'

podman run --rm -v "$PWD/dist":/d:ro docker.io/library/archlinux:latest sh -c \
  'pacman -Sy --noconfirm >/dev/null && pacman -U --noconfirm /d/fettle-*.pkg.tar.zst &&
   fettle --version && fettle -H --dry-run'
```

The Arch container needs `pacman -Sy` first or the `python` dependency cannot be
resolved — again, an empty local database rather than a missing interpreter.

`fettle -H --dry-run` is the check worth running rather than `--version`: it exercises
the six hardening axes, which are loaded by a **computed** module name. If they were not
packaged, the axis framework catches the import error and reports each one as *blind*
rather than crashing — so a broken package would look like a cautious one. Seeing the
axes report real results is what proves the tree is complete.

### One trap worth knowing about the spec file

**rpm expands macros inside comments.** An unescaped `%install` in a comment at the top
of `fettle.spec` made rpm 4.16 (Rocky 9) treat that line as the start of the install
section and swallow the entire preamble — it then reported Name, Version, Release,
Summary and License as missing, none of which was true. rpm 4.20 on the development
machine parsed the same file without complaint, so it failed **only** in a Rocky
container.

Every `%` in a comment in that file is doubled for this reason. It is also the clearest
argument for building each package in its own distro rather than trusting one host:
nothing about the local build hinted at it.
