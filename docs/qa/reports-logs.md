# QA — reports and run-logs (cross-cutting)

Where fettle's own output goes, who can read it, and what counts as a host.

Status: **swept — 2 findings fixed. Deliberately small: fixes only, no redesign, with the
stable release approaching.**

---

## Findings

### R-01 — a run-log was world-readable while it was being written. FIXED
The file was created with the default mode and only chmod'd to `0600` when the run
**finished**, so it sat readable for the whole run — and permanently if the run was
killed. Found in the author's own tree: a 0-byte `0644` log left behind by an interrupted
run.

**Honest severity: defence in depth, not an open door.** Every directory in the tree is
`0700`, so another user cannot traverse into it to read the file. What the fix buys is the
case where that is not true — a tree that predates the `0700` behaviour, a restored
backup, a hand-made directory, a `[reports] dir` pointed somewhere unusual. The file mode
is then the only thing left, and it should not depend on the run reaching its end.

Created `0600` from the moment it exists, for the transcript and its JSON sibling.

### R-02 — `fettle report` counted host *directories*, not hosts. FIXED
It claimed **19 hosts** on a tree with 17. Two of the entries were `fleet` — a **group**
name, left behind by a `fettle remote fleet` that never resolved — and an empty `wopr`.

Both trees still contain those empty directories; the count now looks at what is in them.

## What was already right, and nearly broken

The dashboard **already** hides empty host directories and prints `N empty hidden` —
deliberately, so they do not silently vanish. A first attempt at R-02 filtered them out in
`collect()` instead, which fixed the count and destroyed that message: the number of hidden
hosts became uncomputable.

The test suite caught it. The fix belonged in the summary line added in v0.100.0, which was
the only thing reading the raw directory list — not in the collector that three other
things depend on. *A fix in the wrong layer is not a smaller change, it is a bigger one.*

## Checked and sound

- **Rotation** removes the `.txt` and its `.json` sibling together, keeps at least one
  entry whatever the config says, and sorts chronologically on a fixed-width timestamp.
- **Ownership** is handed back to the invoking user after an elevated run.
- **Directory modes** are `0700` at every level.
- **Dry runs** no longer write logs or reports at all — fixed in the `--dry-run` row, where
  rotation triggered by a dry run was deleting real history.

## Not changed, on purpose

The local machine writes to a host directory called `local` while remote runs use real
hostnames, so this workstation appears as both `local` and (from remote runs) `wopr`.
Renaming it would need a migration for every existing tree, which is not a fix and not
minimal. Recorded here rather than done.
