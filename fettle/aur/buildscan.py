"""Experimental static review of AUR build trees; never sources or executes scripts.

Heuristics identify review points, not a malware verdict. Local input may be stale,
and shell constructs this scanner cannot resolve remain explicit coverage gaps.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import stat
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from ..output import BLIND, FOUND, Output
from ..supplychain.base import Severity

MAX_BYTES = 2 * 1024 * 1024


@dataclass
class Hit:
    severity: Severity
    rule: str
    file: str
    line: int
    detail: str


@dataclass
class ScanResult:
    hits: list[Hit] = field(default_factory=list)
    inspected: list[str] = field(default_factory=list)
    unavailable: list[str] = field(default_factory=list)


def _read(path: Path, *, limit: int = MAX_BYTES) -> bytes:
    # Refuse FIFOs, devices and symlinks, including inside a root-run package audit.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise OSError("not a regular file")
        content = stream.read(limit + 1)
        if len(content) > limit:
            raise OSError("input exceeds the static scan limit")
        return content


def _magic(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise OSError("not a regular file")
        return stream.read(4)


def _local(root: Path, name: str) -> Path:
    path = root / name
    # Every component stays inside the selected tree; symlink components are refused.
    if path.is_absolute() and not path.is_relative_to(root):
        raise OSError("path outside build tree")
    if ".." in Path(name).parts or Path(name).is_absolute():
        raise OSError("path outside build tree")
    if any(p.is_symlink() for p in (root, *root.parents)):
        raise OSError("symlink in build tree path")
    if any((root / Path(*Path(name).parts[:i])).is_symlink()
           for i in range(1, len(Path(name).parts) + 1)):
        raise OSError("symlink in build input")
    return path


def scan_text(text: str, file: str = "PKGBUILD") -> list[Hit]:
    """Inspect literal command tokens, retaining review locations and severity."""
    hits = []
    function = ""
    logical = []
    pending, first = "", 1
    for number, raw in enumerate(text.splitlines(), 1):
        if not pending:
            first = number
        pending += raw
        if raw.endswith("\\") and not raw.endswith("\\\\"):
            pending = pending[:-1] + " "
            continue
        logical.append((first, pending))
        pending = ""
    if pending:
        logical.append((first, pending))
    for number, raw in logical:
        if raw.lstrip().startswith("#"):
            continue
        start = re.match(r"\s*(\w+)\s*\(\)\s*\{", raw)
        if start:
            function = start[1]
        try:
            lexer = shlex.shlex(raw, posix=True, punctuation_chars="|;&(){}")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            # Multi-line strings are not parsed as commands. This is a heuristic,
            # not a shell interpreter; the file report states that limit explicitly.
            continue
        if not tokens:
            continue
        boundaries = {";", "|", "&&", "||", "&", "{", "(", ";;"}
        commands = [(i, token) for i, token in enumerate(tokens)
                    if i == 0 or tokens[i - 1] in boundaries]
        def add(severity, rule, detail):
            hits.append(Hit(severity, rule, file, number, detail))

        download = any(t in ("curl", "wget") for _, t in commands)
        shell_pipe = any(t == "|" and i + 1 < len(tokens) and tokens[i + 1] in ("sh", "bash", "zsh")
                         for i, t in enumerate(tokens))
        decode = any(t == "base64" for _, t in commands) and any(t in ("-d", "--decode") for t in tokens)
        if shell_pipe and download:
            add(Severity.HIGH, "download-shell", "downloaded content is piped into a shell; review the source and execution")
        if shell_pipe and decode:
            add(Severity.HIGH, "decode-shell", "decoded content is executed by a shell, hiding the commands from normal review")
        elif decode:
            add(Severity.LOW, "encoded-content", "base64 decoding appears in build logic; legitimate data decoding is common, so inspect its use")
        if any(t == "eval" for _, t in commands):
            add(Severity.HIGH if any("base64" in t or "curl" in t or "wget" in t for t in tokens) else Severity.MEDIUM,
                "constructed-eval", "eval executes constructed shell text; inspect how that text is produced")
        if any(t == "exec" for _, t in commands) and any("$" in t or "`" in t for t in tokens):
            add(Severity.MEDIUM, "constructed-exec", "exec uses a constructed target; inspect the resolved command")
        if re.search(r"(?:\\x[0-9a-fA-F]{2}){3,}|(?:\\[0-7]{3}){3,}", raw):
            add(Severity.MEDIUM, "escaped-payload", "dense hex/octal escapes obscure text; check what it decodes to")
        if function in ("build", "package") and any(t in ("sudo", "doas") for _, t in commands):
            add(Severity.HIGH, "privileged-build", f"{function} invokes privilege elevation; ordinary package construction should be unprivileged")
        for i, token in commands:
            verbs = {"npm": {"install", "i", "ci"}, "bun": {"install", "add"},
                     "pnpm": {"install", "i", "add"}, "yarn": {"install", "add"},
                     "deno": {"install", "add", "cache"}}
            if i + 1 < len(tokens) and tokens[i + 1] in verbs.get(token, set()):
                add(Severity.MEDIUM, "js-dependencies", f"{token} {tokens[i + 1]} fetches or installs JavaScript dependencies; review lockfiles and install hooks")
            if token.removeprefix("./") in ("validator", "assembler", "optimizer"):
                add(Severity.LOW, "helper-provenance", f"{token} is invoked as a build helper; the name alone is weak evidence, so verify its provenance")
        if download and shell_pipe and decode:
            add(Severity.CRITICAL, "download-decode-execute", "a downloaded, encoded payload is decoded and executed; investigate before building")
        if raw.strip() == "}":
            function = ""
    return hits


def _expand_literal(value: str, variables: dict[str, str]) -> str | None:
    value = re.sub(r"\$\{(pkgname|pkgbase)\}|\$(pkgname|pkgbase)\b",
                   lambda m: variables.get(m[1] or m[2]) or m[0], value)
    return None if "$" in value or "`" in value else value


def scan_directory(directory: Path, *, package: str = "", previous: Path | None = None) -> ScanResult:
    root = directory.absolute()
    result = ScanResult()
    try:
        text = _read(_local(root, "PKGBUILD")).decode("utf-8")
    except (OSError, UnicodeError):
        result.unavailable.append("PKGBUILD could not be read as a regular UTF-8 file")
        return result
    result.inspected.append("PKGBUILD")
    result.hits.extend(scan_text(text))
    compare = previous is not None
    if compare:
        try:
            _read(_local(previous.absolute(), "PKGBUILD")).decode("utf-8")
        except (OSError, UnicodeError):
            result.unavailable.append("previous PKGBUILD could not be read; install-script comparison unavailable")
            compare = False
    variables = {"pkgname": package, "pkgbase": package}
    for key in ("pkgname", "pkgbase"):
        match = re.search(rf"(?m)^\s*{key}\s*=\s*['\"]?([A-Za-z0-9@._+-]+)['\"]?\s*(?:#.*)?$", text)
        if match:
            variables[key] = match[1]
    installs = {p.name for p in root.glob("*.install")}
    declared = re.search(r"(?m)^\s*install\s*=\s*(.+)$", text)
    if declared:
        try:
            words = shlex.split(declared[1], comments=True)
        except ValueError:
            words = []
        literal = _expand_literal(words[0], variables) if len(words) == 1 else None
        if literal:
            installs.add(literal)
        else:
            result.unavailable.append("install declaration is dynamic and could not be resolved statically")
    for name in sorted(installs):
        try:
            content = _read(_local(root, name)).decode("utf-8")
        except (OSError, UnicodeError):
            result.unavailable.append(f"install script {name} could not be read safely")
            continue
        result.inspected.append(name)
        result.hits.extend(scan_text(content, name))
        if compare and not (previous / name).exists():
            result.hits.append(Hit(Severity.MEDIUM, "new-install-script", name, 1,
                                   "install script was absent from the supplied previous tree; review the new hook"))

    upstream_match = re.search(r"(?m)^\s*url\s*=\s*['\"]?([^'\"\s]+)", text)
    try:
        upstream = urlsplit(upstream_match[1]).hostname if upstream_match else None
    except ValueError:
        upstream = None
        result.unavailable.append("declared upstream URL could not be parsed")
    for match in re.finditer(r"(?ms)^\s*source(?:_\w+)?\s*=\s*\((.*?)\)", text):
        try:
            sources = shlex.split(match[1], comments=True)
        except ValueError:
            result.unavailable.append("source array could not be resolved statically")
            continue
        for raw in sources:
            expanded = _expand_literal(raw, variables)
            if expanded is None:
                result.unavailable.append(f"dynamic source entry could not be resolved: {raw}")
                continue
            value = expanded.split("::", 1)[-1]
            if "://" in value:
                try:
                    host = urlsplit(value).hostname
                except ValueError:
                    result.unavailable.append("source URL could not be parsed")
                    continue
                if upstream and host and host != upstream and not host.endswith("." + upstream):
                    result.hits.append(Hit(Severity.LOW, "source-host", "PKGBUILD", text[:match.start()].count("\n") + 1,
                                           f"source host {host} differs from declared upstream {upstream}; mirrors/CDNs may explain this"))
                continue
            try:
                magic = _magic(_local(root, value))
            except OSError:
                result.unavailable.append(f"local source {value} could not be read safely")
                continue
            result.inspected.append(value)
            if magic == b"\x7fELF":
                result.hits.append(Hit(Severity.HIGH, "local-elf", value, 1,
                                       "ELF binary is a local source artifact; verify its provenance instead of trusting source-build expectations"))
    return result


def cached_directories(home: Path, package: str, *, user: str = "") -> list[Path]:
    if not re.fullmatch(r"[A-Za-z0-9@._+-]+", package) or package in (".", ".."):
        return []
    candidates = [home / ".cache" / helper / package for helper in ("yay", "paru", "pamac")]
    if user and re.fullmatch(r"[A-Za-z0-9_-]+", user):
        candidates.append(Path(f"/var/tmp/pamac-build-{user}") / package)
    return [path for path in candidates if path.is_dir()]


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fettle aur-build-scan",
                                description="Experimental static PKGBUILD/install-script review; executes nothing and does not certify safety.")
    p.add_argument("directory", type=Path, help="local build tree containing PKGBUILD")
    p.add_argument("--previous", type=Path, help="previous local tree for new install-script comparison")
    p.add_argument("--no-color", action="store_true", help="plain text output")
    return p


def main(argv) -> int:
    args = parser().parse_args(argv)
    out = Output(color=False if args.no_color else None)
    out.current_action = "aur-build-scan"
    out.section("AUR build-script review (experimental)")
    result = scan_directory(args.directory, previous=args.previous)
    for hit in result.hits:
        out.warn(f"[{hit.severity.label}] {hit.file}:{hit.line} {hit.rule}: {hit.detail}")
    for gap in result.unavailable:
        out.not_checked(gap)
    if result.unavailable:
        out.summary_fail(f"{len(result.unavailable)} build input(s) could NOT be inspected", kind=BLIND)
    if result.hits:
        out.summary_fail(f"{len(result.hits)} review finding(s)", kind=FOUND)
    elif not result.unavailable:
        out.summary_add(f"{len(result.inspected)} file(s) inspected; no heuristic matched (not a safety guarantee)")
    out.note("Static heuristics only; cached files may be stale. Review complete scripts before building.")
    out.print_summary()
    return int(out.had_failures)
