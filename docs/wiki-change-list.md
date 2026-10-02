# Wiki handoff for 1.21.0

Prepared 2026-10-02. The separate GitHub wiki was not edited or migrated. These
page names are the existing links from the repository README; the changes below
are proposed section edits, to be reconciled with page contents when applied.

| Wiki page / section | Required correction | Repository reference |
| --- | --- | --- |
| [Maintenance actions](https://github.com/pasadoorian/fettle/wiki/Maintenance-actions) / previews and failure output | Failed apt/pacman simulations are failures, not empty pending sets. Keep single-action vs everything exit categories. | [architecture](architecture.md), [changelog](../CHANGELOG.md) |
| [Package supply-chain](https://github.com/pasadoorian/fettle/wiki/Package-supply-chain) / AUR precheck and hook | Add shared experimental static review, build-dir/build-only, cached audit gaps, severities and no-execution limits. Hook deployment needs updating. | [AUR review](aur-build-review.md) |
| [System hardening audit](https://github.com/pasadoorian/fettle/wiki/System-hardening-audit) / axes and prerequisites | Ten axes; checksec is needed for the binary axis only. Document extra certificate/filesystem paths, disable_axes and auditing experimental status. | [example config](../fettle.toml.example), [README](../README.md) |
| [System supply-chain](https://github.com/pasadoorian/fettle/wiki/System-supply-chain) / firmware tooling | Chipsec requires secure.chipsec_cmd; do not claim automatic detection. Preserve physical-hardware gaps. | [example config](../fettle.toml.example), [issue index](issues.md) |
| [Security advisories](https://github.com/pasadoorian/fettle/wiki/Security-advisories) / OSV cache and coverage | Inventory-based invalidation, paging, incomplete-record rejection, invoking-user environments and Debian source-version matching. Remove advice for the retired warn_gate option; preserve current gate behavior. | [architecture](architecture.md), [issues](issues.md) |
| [Remote maintenance](https://github.com/pasadoorian/fettle/wiki/Remote-maintenance) / interpreter and fetch-back | Python 3.11+ is required even if python3 is older; supported versioned executables are selected. State unresolved custom remote reports.dir discovery. | [architecture](architecture.md), [verification](maintenance-verification.md) |
| [Configuration and reporting](https://github.com/pasadoorian/fettle/wiki/Configuration-and-reporting) / validation, retention and UI | Valid siblings survive invalid settings; numeric collision ordering, private atomic paired writes, unknown old log statuses and malformed payload coverage. Experimental UI requires loopback Host and same-origin HTTP/WS. | [example config](../fettle.toml.example), [architecture](architecture.md) |
| [AI upgrade check](https://github.com/pasadoorian/fettle/wiki/AI-upgrade-check) / remote errors | Authentication/collection/analysis failures return nonzero with blindness; the AI structured-output migration remains deferred. | [issues](issues.md), [changelog](../CHANGELOG.md) |
| [Reference](https://github.com/pasadoorian/fettle/wiki/Reference) / development and release | Reviewed constraints/setup script, Python 3.11–3.14 matrix, optional-web tests, draft-only repair guard and current architectural contracts. | [dependencies](dependencies.md), [architecture](architecture.md), [packaging](../packaging/README.md) |

Link the issue index as current status alongside historical QA records. Preserve
original evidence, dates and case IDs; new verification must not imply that all
hardware, API-cost or interactive cases were rerun.
