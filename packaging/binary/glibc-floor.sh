#!/bin/sh
# Highest required GLIBC symbol version across the native build's ELF payload.
# Version definitions are not requirements: only readelf's needs sections count.
set -eu
command -v readelf >/dev/null 2>&1 || {
    echo 'glibc-floor: readelf is required to describe the native artifact' >&2
    exit 1
}
[ "$#" -gt 0 ] || { echo 'usage: glibc-floor.sh BUILD_DIRECTORY' >&2; exit 1; }
minimum=$(find "$@" -type f \( -name '*.so' -o -name '*.so.*' -o -name '*.bin' -o -name 'fettle' \) \
    -exec readelf --version-info {} \; 2>/dev/null | \
    awk '/Version needs section/ { needs=1; next } /Version (symbols|definition) section/ { needs=0 } needs { print }' | \
    grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sed 's/^GLIBC_//' | sort -Vu | tail -n 1)
[ -n "$minimum" ] || { echo 'glibc-floor: no GLIBC requirements were found' >&2; exit 1; }
printf '%s\n' "$minimum"
