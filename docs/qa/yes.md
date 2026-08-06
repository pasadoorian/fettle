# QA — `--yes` semantics (cross-cutting)

**The rule fettle already follows, written down:** `--yes` answers *questions*. It does not
override a *safety judgement*.

That distinction was not invented for this row — it is visible in two places already. A
CRITICAL AUR pre-check finding needs `--force-aur` **on top of** `--yes` before an install
proceeds. Container images awaiting confirmation are **skipped** under `--yes` rather than
auto-approved. This row checks the rest of the surface agrees.

Status: **swept — 1 finding fixed.** Deliberately minimal, with the stable release close.

---

## Finding

### Y-01 — `--yes` auto-purged an orphan list fettle had *inferred*. FIXED

`deborphan` no longer exists in Debian 13 or Ubuntu 26.04, so v0.94.0 added a fallback that
answers the same question from dpkg's own data — fettle's **own reverse-dependency scan**.

Under `--yes`, `select()` returns every item, and the purge then runs with `apt-get purge
-y`. So `fettle -o --yes` on a modern Debian would remove every package a **heuristic**
guessed at, with apt's own confirmation suppressed as well. No human anywhere in the loop,
on the output this project's own notes call "the most dangerous fettle produces".

The risk arrived with the fallback, eleven releases ago, and is exactly the shape the AUR
gate already guards against.

**Fixed by applying the existing rule:** when the list came from fettle's inference rather
than a dedicated tool, an unattended run reports it and removes nothing. `deborphan`'s
verdict is a tool's and keeps its previous behaviour; interactive runs are untouched, since
a human is present to review per package.

## Checked and already right

- **Kernels** — the removable list excludes running ∪ newest *before* `--yes` sees it, so
  an unattended run cannot purge a kernel you depend on. `-k` is also outside the default
  set.
- **Containers** — images awaiting confirmation are skipped under `--yes`, with a next-step
  pointing at `[containers] always_update` for anyone who wants them included.
- **AUR** — a CRITICAL pre-check finding blocks an unattended upgrade unless `--force-aur`
  is also given.
- **Arch orphans** — the candidate list is `pacman -Qtdq`, the package manager's own
  verdict rather than fettle's inference, so the same rule leaves it alone.
- **`confirm()` / `select()`** — `--yes` answers yes and selects all, which is the point of
  the flag. The guard belongs at the call site that knows whether the list is trustworthy,
  not in the primitive.

## The rule for anything added later

If `--yes` would let fettle act on a list **fettle itself inferred**, guard it. If the list
is a tool's verdict, `--yes` may proceed. When in doubt the safe direction is to report and
skip: an unattended run that did less than asked is recoverable, and one that removed the
wrong package is not.
