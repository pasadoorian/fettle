# Packaging

Three distro packages, all built from one staged layout so they cannot drift apart.

```
packaging/
  install.sh          stages the installed tree into $DESTDIR — the single source of layout
  version.sh          prints the version from pyproject.toml — the single source of version
  deb/build.sh        → dist/fettle_<version>_all.deb
  rpm/build.sh        → dist/fettle-<version>-1.noarch.rpm      (+ fettle.spec)
  arch/build.sh       → dist/fettle-<version>-1-any.pkg.tar.zst (+ PKGBUILD)
```

Every script writes to `dist/`, which is gitignored, and takes an optional output
directory as its first argument.

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
