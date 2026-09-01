"""The startup inventory, and what changed since the last time you looked.

The ownership checks in :mod:`fettle.compromise.persistence` answer *did anybody sanction
this being here*. They are good at it, and there is one thing they structurally cannot
see: **a file that a package owns, whose contents were edited in place.** `dbus.service`
still belongs to `dbus` after somebody rewrites its `ExecStart`, so no ownership test will
ever mention it.

That is the gap this fills, and it is the only new finding here. Everything else is
inventory: every startup file on the machine, what class it is, who owns it and when it
last changed, written to the saved report so there is something to read when a question
comes up later.

## The baseline enriches, it never gates

This matters more than any other decision in the module. **The ownership checks run
identically whether or not a baseline exists.** The baseline only ever adds a sentence to
a finding that would have been reported anyway, or raises a change nothing else could see.

The reason is the poisoned baseline. If the first run happens on a machine that is already
compromised, the implant is recorded as normal. A design where the baseline decides what
gets reported would then go permanently quiet about it, and the machine that most needed
the check would be the one that said least. Built this way, an implant present at baseline
time is still unowned, so it is still reported, just without the timing.

## Content, not timestamps

Entries carry a sha256 of the file rather than its mtime. `touch -r reference victim`
backdates an mtime in one command and cannot forge a hash, and hashing seven hundred small
text files costs milliseconds. The mtime is still recorded, because it is useful to a
human reading the inventory, and it is never what a comparison turns on.

## The first run has nothing to compare against, and says so

"Baseline recorded, 702 entries" and "nothing changed" are different statements, and
rendering the first as the second is the same failure the axis contract exists to prevent.
The date the baseline was taken is printed on every run that uses one, so a baseline
captured at the wrong moment is visible rather than silent.

## A change is reported once, and the limit of that is stated rather than hidden

The baseline is rewritten at the end of every run, so a modified file is reported on the
run that finds it and the new contents become the comparison point for the next one.
Observed while verifying this on the Debian lab VM: appending a line to a package-owned
unit was reported, and *restoring* the file was reported too, because relative to the
baseline written a minute earlier the restore was itself a change. The run after that was
clean.

That is the right behaviour for the common case, which is a package upgrade rewriting a
unit, and it would be unusable otherwise: every upgraded file would be reported on every
run forever. **The cost is that a change nobody reads is absorbed.** If a compromise lands
between two runs and the run that reports it goes unseen, the next run treats the implant
as the norm.

What limits the damage is that this was built to enrich rather than to gate. The
ownership checks never consult the baseline, so an implanted file that no package owns
keeps being reported on every run for as long as it is there, with or without a baseline.
What is lost after the first report is the *timing*, not the finding.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from . import MEDIUM, CheckResult, Finding

#: Bumped when the stored shape changes. An older or unreadable file is discarded and
#: re-taken rather than guessed at, and the run says it did so.
VERSION = 1

FILENAME = "startup-baseline.json"


def path_for(ctx) -> Path:
    """Where the baseline lives, next to the reports and under the same config key.

    Uses the reports resolver rather than a second one of its own, so ``[reports] dir``
    moves both and a run under sudo writes to the invoking user's home rather than root's.
    """
    from .. import reports

    return reports._settings(ctx)[0] / FILENAME


def digest(path: Path) -> str:
    """sha256 of a file, or "" when it cannot be read."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def snapshot(subjects: list[tuple[Path, str]], owners: dict[str, str]) -> dict:
    """``{path: {"class", "sha256", "package", "mtime"}}`` for everything examined."""
    out: dict[str, dict] = {}
    for path, kind in subjects:
        key = str(path)
        try:
            mtime = int(path.stat().st_mtime)
        except OSError:
            mtime = 0
        out[key] = {"class": kind, "sha256": digest(path),
                    "package": owners.get(key, ""), "mtime": mtime}
    return out


def load(path: Path) -> dict | None:
    """The stored baseline, or None when there is not a usable one.

    Any malformed or future-versioned file reads as absent. The run then records a fresh
    one and says it did, which is honest; silently comparing against half a file would
    not be.
    """
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("version") != VERSION:
        return None
    if not isinstance(data.get("entries"), dict):
        return None
    return data


def save(path: Path, entries: dict, *, now=None) -> bool:
    """Write the baseline owner-only from the start. True when it was written.

    ``O_CREAT`` with the mode rather than create-then-chmod, for the reason recorded in
    :func:`fettle.runlog._open_private`: the window between the two is when a shared
    machine can read it, and an interrupted run leaves it open permanently.
    """
    payload = {"version": VERSION, "taken": int(now if now is not None else time.time()),
               "entries": entries}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(payload, fh)
    except OSError:
        return False
    return True


def compare(old: dict, new: dict) -> dict[str, list[str]]:
    """What moved between two snapshots.

    ``changed`` is the one nothing else in fettle can see. ``appeared`` and ``lost_owner``
    are context for findings the ownership checks already raise, and ``removed`` is report
    material: a package removal produces those in bulk and none of them is a risk.
    """
    changed, appeared, removed, lost = [], [], [], []
    for key, entry in sorted(new.items()):
        before = old.get(key)
        if before is None:
            appeared.append(key)
            continue
        # An empty digest means unreadable on one side or the other, and comparing it
        # against a real hash would report every unreadable file as modified.
        if before.get("sha256") and entry.get("sha256") \
                and before["sha256"] != entry["sha256"]:
            changed.append(key)
        if before.get("package") and not entry.get("package"):
            lost.append(key)
    removed = sorted(set(old) - set(new))
    return {"changed": changed, "appeared": appeared,
            "removed": removed, "lost_owner": lost}


def _when(taken: int) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(taken))


def apply(ctx, res: CheckResult, subjects: list[tuple[Path, str]],
          owners: dict[str, str]) -> set[str]:
    """Record the inventory, compare against the baseline, and return what is new.

    The returned set is the enrichment: paths the ownership checks are about to report
    anyway, which were not here when the baseline was taken. It is empty on a first run
    and on a run where the baseline could not be read, so a caller that uses it adds
    nothing rather than claiming something false.
    """
    new = snapshot(subjects, owners)
    by_class: dict[str, int] = {}
    for entry in new.values():
        by_class[entry["class"]] = by_class.get(entry["class"], 0) + 1
    res.notes.append("startup inventory: " + ", ".join(
        f"{n} {kind}" for kind, n in sorted(by_class.items())) +
        " (the full list is in the saved report)")
    res.detail_rows.extend(
        f"{e['class']:<10} {time.strftime('%Y-%m-%d', time.localtime(e['mtime']))}  "
        f"{e['package'] or '(no package)':<24} {key}"
        for key, e in sorted(new.items()))

    store = path_for(ctx)
    old = load(store)

    if old is None:
        # Never silently. A first run and a run where nothing changed look identical in
        # every way except what they are entitled to claim, so the difference is stated.
        if getattr(ctx, "dry_run", False):
            res.notes.append(
                "no startup baseline yet, and --dry-run does not write one, so nothing "
                "here is a comparison against a previous run")
        elif save(store, new):
            res.notes.append(
                f"startup baseline recorded, {len(new)} entries. This run had nothing to "
                f"compare against; the next one will report what changed since today")
        else:
            res.blind.append((
                "changes since the last run were NOT compared",
                f"the baseline could not be written to {store}, so this run cannot say "
                f"what changed and neither will the next one", ""))
        return set()

    diff = compare(old["entries"], new)
    taken = _when(old.get("taken", 0))
    res.notes.append(
        f"compared against the startup baseline taken {taken}: "
        f"{len(diff['appeared'])} new, {len(diff['changed'])} modified, "
        f"{len(diff['removed'])} gone")
    res.detail_rows.extend(f"removed since {taken}: {p}" for p in diff["removed"])

    # The one finding here, and the only one in fettle that can see a package-owned file
    # edited in place without asking the package manager for a hash it may not have.
    for key in diff["changed"]:
        entry = new[key]
        owner = entry["package"]
        res.findings.append(Finding(
            check="startup-file-changed", subject=key, severity=MEDIUM,
            summary=f"contents changed since {taken}",
            detail=(f"this file's contents are not what they were when the baseline was "
                    f"taken on {taken}"
                    + (f", and it still belongs to {owner}, so no ownership check will "
                       f"mention it" if owner else ", and no package owns it") + "."),
            fix=f"see what it does now: cat {key}"))

    for key in diff["lost_owner"]:
        res.notes.append(
            f"{key} was owned by {old['entries'][key]['package']} at the baseline and is "
            f"owned by nothing now, which usually means the package was removed and the "
            f"file was left behind")

    if not getattr(ctx, "dry_run", False):
        save(store, new)
    return set(diff["appeared"])
