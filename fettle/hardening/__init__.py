"""Binary hardening audit — did a package escape the distro's own build policy?

Not a generic lint: the baseline is what the distro *declares* it builds with
(Arch ``makepkg.conf`` + GCC's compiled-in defaults; Debian ``dpkg-buildflags``),
so a deviation means the package was built differently from everything else on
the system — an upstream Makefile clobbering CFLAGS, a vendored prebuilt binary,
or a sloppy AUR build.
"""
