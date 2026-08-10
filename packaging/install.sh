#!/bin/sh
# Stage fettle's installed layout into $DESTDIR.
#
# All three distro packages (.deb, .rpm, .pkg.tar.zst) install the identical tree, so
# they all call this rather than each describing the layout themselves. Three copies of
# a file list is three places for it to drift, and the one that drifts is always the one
# nobody built recently.
#
#   usage: packaging/install.sh DESTDIR [PREFIX]
#
# Layout, and why it is not a python site-packages directory:
#
#   /usr/lib/fettle/fettle/…   the package
#   /usr/bin/fettle            wrapper that puts the above on PYTHONPATH
#   /usr/share/bash-completion/completions/fettle
#   /usr/share/doc/fettle/     README, LICENSE, fettle.toml.example
#
# site-packages would couple the install to a python MINOR version on Arch and RHEL
# (/usr/lib/python3.13/site-packages), so a python upgrade would strand it — the exact
# breakage `fettle -y` exists to detect in other people's packages. Debian's
# dist-packages is version-independent, but using two different layouts for two families
# is worse than one layout that works everywhere. fettle is a CLI, not a library, so
# nothing needs to `import fettle`.
set -eu

DESTDIR="${1:?usage: install.sh DESTDIR [PREFIX]}"
PREFIX="${2:-/usr}"
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

libdir="$DESTDIR$PREFIX/lib/fettle"
bindir="$DESTDIR$PREFIX/bin"
compdir="$DESTDIR$PREFIX/share/bash-completion/completions"
docdir="$DESTDIR$PREFIX/share/doc/fettle"

mkdir -p "$libdir" "$bindir" "$compdir" "$docdir"

# The package itself, without build droppings. Mirrors what remote.build_zipapp already
# excludes, so the shipped tree and the one sent to remote hosts stay the same thing.
cp -R "$here/fettle" "$libdir/"
find "$libdir" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$libdir" -name '*.py[co]' -delete 2>/dev/null || true

# Byte-compile, because /usr/lib is root-owned: a normal user's interpreter cannot write
# __pycache__ there and would recompile on every run.
#
# Measured before claiming it mattered, and it barely does — about 2 ms per invocation
# (0.665 s vs 0.683 s over ten runs of the completion helper, which is the hottest path
# fettle has). It stays because it is free at install time and it is what every distro's
# python tooling does anyway, not because it is load-bearing. If the .pyc go stale after
# a python upgrade, python falls back to the .py beside them: slower, never wrong.
python3 -m compileall -q "$libdir/fettle" >/dev/null 2>&1 || true

cat > "$bindir/fettle" <<EOF
#!/bin/sh
# fettle lives in $PREFIX/lib/fettle rather than site-packages — see packaging/install.sh.
PYTHONPATH="$PREFIX/lib/fettle\${PYTHONPATH:+:\$PYTHONPATH}"
export PYTHONPATH
exec python3 -m fettle "\$@"
EOF
chmod 755 "$bindir/fettle"

install -m 644 "$here/contrib/fettle.bash" "$compdir/fettle"
install -m 644 "$here/README.md" "$docdir/README.md"
install -m 644 "$here/LICENSE" "$docdir/LICENSE"
install -m 644 "$here/fettle.toml.example" "$docdir/fettle.toml.example"
