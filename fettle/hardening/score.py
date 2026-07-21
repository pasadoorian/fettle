"""Risk scoring for hardening deviations.

Each binary's score is the weighted sum of the protections it's *missing*
(computed on post-exclusion findings — an excluded check contributes nothing),
multiplied by a privilege factor when the binary is a privilege boundary
(setuid/setgid, or in a user-named ``sensitive_packages`` list). Scores map to
four bands. Weights, the multiplier, and the sensitive list are config-tunable;
the band thresholds are calibrated against a real system and kept as constants.
"""

from __future__ import annotations

import fnmatch
import os

# checksec key -> risk weight. Higher = the mitigation matters more. `nx` is here
# for completeness though it's effectively always present.
DEFAULT_WEIGHTS = {
    "canary": 3.0,          # stack-smash detection — the classic overflow guard
    "relro": 3.0,           # GOT-overwrite hardening
    "pie": 2.0,             # ASLR effectiveness
    "fortify_source": 2.0,  # bounds-checked libc wrappers
    "cfi": 1.0,             # newest hardware guardrail; commonly absent upstream
    "rpath": 1.0,           # insecure library search path
    "runpath": 0.5,         # non-standard search path (mild hygiene smell)
    "nx": 4.0,
}
DEFAULT_PRIV_MULT = 3.0

# (band, inclusive-minimum score), highest first. Calibrated to a live score
# distribution (range ~0.5..18, median ~2): a setuid binary missing canary+relro
# lands Critical; a non-priv binary missing several lands High; the bulk is Low.
BANDS = (("Critical", 14.0), ("High", 8.0), ("Medium", 3.0), ("Low", 0.01))
BAND_ORDER = ["Critical", "High", "Medium", "Low"]


def is_setuid(path: str) -> bool:
    """True if the file has the setuid or setgid bit — a privilege boundary."""
    try:
        return bool(os.stat(path).st_mode & 0o6000)
    except OSError:
        return False


def band(score: float) -> str:
    for name, floor in BANDS:
        if score >= floor:
            return name
    return "none"


class Scorer:
    """Turns a binary's missing-check set into a risk score, per config."""

    def __init__(self, weights=None, priv_mult=DEFAULT_PRIV_MULT,
                 sensitive_packages=None):
        self.weights = {**DEFAULT_WEIGHTS, **(weights or {})}
        self.priv_mult = float(priv_mult)
        self.sensitive_packages = list(sensitive_packages or [])

    @classmethod
    def from_config(cls, cfg) -> "Scorer":
        h = getattr(cfg, "hardening", None) or {}
        if not isinstance(h, dict):
            return cls()
        weights = h.get("weights")
        weights = {str(k): float(v) for k, v in weights.items()} \
            if isinstance(weights, dict) else None
        try:
            priv = float(h.get("priv_multiplier", DEFAULT_PRIV_MULT))
        except (TypeError, ValueError):
            priv = DEFAULT_PRIV_MULT
        sens = h.get("sensitive_packages")
        sens = [str(x) for x in sens] if isinstance(sens, (list, tuple)) else None
        return cls(weights=weights, priv_mult=priv, sensitive_packages=sens)

    def is_sensitive_pkg(self, pkg: str) -> bool:
        return any(fnmatch.fnmatch(pkg, g) for g in self.sensitive_packages)

    def is_privileged(self, path: str, pkg: str) -> bool:
        return is_setuid(path) or self.is_sensitive_pkg(pkg)

    def binary_score(self, missing_checks, *, privileged: bool) -> float:
        base = sum(self.weights.get(c, 1.0) for c in missing_checks)
        return round(base * (self.priv_mult if privileged else 1.0), 2)
