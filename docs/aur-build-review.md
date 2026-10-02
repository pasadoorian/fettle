# Experimental AUR build-script review

`fettle aur-build-scan DIR` reads a local build tree containing `PKGBUILD`. It
never sources the build file, runs hooks, fetches artifacts, or invokes a build.
Findings are review points with Critical/High/Medium/Low severity, file and line,
and an explanation. A match is not a malware verdict; no match does not certify safety.

```sh
fettle aur-build-scan /path/to/build-tree
fettle aur-build-scan /path/to/current --previous /path/to/previous
fettle aur-precheck PACKAGE --build-dir /path/to/fetched-tree
fettle aur-precheck PACKAGE --build-dir /path/to/fetched-tree --build-only
```

One engine serves the standalone command, the explicit `aur-precheck` build-directory
option, and `pkg-audit`'s AUR provider. The updated [yay hook](../contrib/yay-init.lua)
passes yay's already-fetched directory to the precheck. Reinstall that hook after
updating fettle. Legacy/override helpers and missing yay directory data produce a
coverage warning. The hook remains advisory; it does not block yay's install menu.

`pkg-audit` inspects available yay, paru and pamac package-base caches belonging to
the invoking user. These may describe a different revision from the installed package.
It reports missing trees and unresolved inputs as `UNVERIFIABLE`, alongside metadata
and IOC findings. It does not create or refresh a cache. Script hits use the additive
`BUILD_LOGIC` question, rather than the `KNOWN_BAD` label reserved for known IOCs.

The engine reviews downloaded content piped to a shell, encoded execution, constructed
`eval`/`exec`, dense shell escapes, privilege elevation in build/package functions,
and dependency installs using npm, bun, pnpm, yarn and deno. Literal local sources are
checked for ELF headers. Declared upstream/source host differences and helper names
such as `validator` are weak signals: legitimate mirrors and helpers are common.
A readable `--previous` tree enables an explicit new-install-script comparison;
there is no automatic historical baseline or implicit git/network fetch.

Unreadable, non-UTF-8, oversized, symlinked and nonregular scripts produce coverage
gaps. Dynamic source/install expressions remain unresolved. Inputs are bounded to
2 MiB per script; local source binaries require only a four-byte header read.
This is a token/regex heuristic, not a shell parser: functions, multiline strings,
heredocs, aliases and generated commands can evade it or cause false positives.
Review complete scripts and source provenance before deciding to build.

The standalone command exits nonzero for any finding or coverage gap. The precheck
retains its CRIT/WARN stdout contract and exits nonzero only for Critical findings.
`AUR_PRECHECK=0` disables metadata/IOC checks; an explicitly requested build-directory
review still runs. `--build-only` skips metadata/IOC checks without an environment
change. `YAY_AUR_PRECHECK=0` preserves local review while skipping the network gate.
The Python allowlist suppresses metadata checks only after ownership/mode validation;
it does not suppress an explicit local build review.

See [verification](maintenance-verification.md) for the exercised fixtures and
[issues](issues.md) for remaining coverage limitations.
