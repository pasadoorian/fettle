"""Every fettle flag mentioned in prose must be one fettle still accepts.

The project's own notes call this "the post-v0.4.0 stale-flag class of bug": after a
rename, user-facing strings keep advising the old spelling. It has now bitten five
times — `-S` meaning aur-ioc-scan, `-p` meaning config-drift, and `-I` three separate
times *after* it was retired, including the web UI still offering it as a runnable
action. Grepping for the action NAME missed all three, because all three spelled it
`-I`.

So this is a test rather than a habit. The valid set is read from the parsers
themselves, so it cannot drift from what fettle actually accepts.
"""

import re
import subprocess
import sys
from pathlib import Path

from fettle import cli

ROOT = Path(__file__).resolve().parent.parent
SUBCOMMANDS = ("sys-audit", "upgrade-check", "aur-precheck", "advisory-check",
               "advisory-update", "report", "web", "remote")

# `fettle` as a WORD, not the `.fettle` in a path -- otherwise `pacman -Qtdq` on a line
# mentioning ~/.fettle/reports/ looks like one of ours.
_CTX = re.compile(r"(?<![.\w])fettle[^\n`'\"]{0,80}?(?<![\w-])(-{1,2}[A-Za-z][\w-]*)")
_TICKED = re.compile(r"`(?<![\w-])(-{1,2}[A-Za-z][\w-]*)`")
# Backticked invocations only. A line that merely starts with "fettle" is usually prose
# ("fettle refuses to...") and treating those as commands gives ~100 false positives.
_WORD = re.compile(r"`fettle\s+([a-z][a-z0-9-]{2,})")
_SSH_OPT = re.compile(r"^-o[A-Z]")               # `-oProxyCommand=…` is ssh's, not ours

# History, not advice: these record retired spellings on purpose.
_SKIP_PARTS = {".git", "venv-fettle-dev", "__pycache__", "matrix-logs"}
# This file deliberately contains retired spellings, in its own canary.
_SKIP_FILES = {"CHANGELOG.md", "PLAN.md", "test_stale_flags.py"}
_SKIP_DIRS = ("docs/qa",)


def _valid() -> tuple[set, set]:
    parser = cli.build_parser()
    flags = {o for a in parser._actions for o in a.option_strings}
    for cmd in SUBCOMMANDS:                      # each subparser owns its own flags
        help_text = subprocess.run(
            [sys.executable, "-m", "fettle", cmd, "--help"],
            capture_output=True, text=True, cwd=ROOT).stdout
        flags |= set(re.findall(r"(?:^|\s)(--?[A-Za-z][A-Za-z0-9-]*)", help_text))
    words = ({w.replace("_", "-") for w in cli.ACTION_NAMES} | set(cli.ACTION_NAMES)
             | set(cli.WORD_ALIASES) | set(SUBCOMMANDS))
    return flags, words


def _files():
    for f in ROOT.rglob("*"):
        rel = f.relative_to(ROOT)
        if (f.is_file() and f.suffix in (".py", ".md", ".lua", ".toml")
                and not any(p in _SKIP_PARTS for p in f.parts)
                and f.name not in _SKIP_FILES
                and not str(rel).startswith(_SKIP_DIRS)):
            yield rel, f


def sweep() -> list[str]:
    flags, words = _valid()
    hits = []
    for rel, f in _files():
        try:
            text = f.read_text()
        except (OSError, UnicodeDecodeError):     # pragma: no cover - binary/permission
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if "retir" in line.lower():           # a line SAYING a flag is retired
                continue
            found = set(_CTX.findall(line))
            if re.search(r"(?<![.\w])fettle\b", line):
                found |= set(_TICKED.findall(line))
            hits += [f"{rel}:{n}: {t} -- {line.strip()[:70]}"
                     for t in found if t not in flags and not _SSH_OPT.match(t)]
            hits += [f"{rel}:{n}: {w} -- {line.strip()[:70]}"
                     for w in _WORD.findall(line) if w not in words and w not in flags]
    return sorted(hits)


def test_no_stale_flag_references():
    stale = sweep()
    assert not stale, "flags fettle no longer accepts:\n  " + "\n  ".join(stale)


def test_the_sweep_can_actually_see_a_stale_reference(tmp_path, monkeypatch):
    """A sweep that finds nothing because it is broken looks exactly like a clean one
    — the invariant this whole QA pass is about, applied to its own checker."""
    canary = ROOT / "_stale_flag_canary.md"
    canary.write_text("Run `fettle -I` then `fettle aur-ioc-scan`, "
                      "or `fettle --totally-made-up`.\n"
                      "But `fettle -p pkg` is real and `pacman -Qtdq` is not ours.\n")
    try:
        found = " ".join(sweep())
    finally:
        canary.unlink()
    assert "-I" in found and "aur-ioc-scan" in found and "--totally-made-up" in found
    assert "-p" not in found.replace("--totally-made-up", "") and "-Qtdq" not in found
