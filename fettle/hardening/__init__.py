"""System hardening audit — is this machine hardened, along several axes?

The oldest and largest axis is the **binary** one, and it is the reason for the
modules here (``baseline``, ``engine``, ``report``, ``score``): did a package escape
the distro's own build policy? Not a generic lint — the baseline is what the distro
*declares* it builds with (Arch ``makepkg.conf`` + GCC's compiled-in defaults; Debian
``dpkg-buildflags``), so a deviation means the package was built differently from
everything else on the system: an upstream Makefile clobbering CFLAGS, a vendored
prebuilt binary, or a sloppy AUR build.

The other axes live in :mod:`fettle.hardening.axes`, one module each, and answer
questions about the running system rather than about how its binaries were compiled.
They are independent by design — see that package's docstring for why.
"""
