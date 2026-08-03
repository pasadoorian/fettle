

# -- the summary mark has to match what was found -----------------------------
def _audit_with(findings, capsys, tmp_path):
    from fettle import actions
    from fettle.backends.base import Context
    from fettle.config import Config
    from fettle.output import Output

    class _P:
        source, coverage = "test", "cov"

        def is_present(self, ctx):
            return True

        def findings(self, ctx):
            return findings

    class _B:
        def supply_chain_sources(self):
            return [_P()]

    ctx = Context(output=Output(color=False), config=Config(), dry_run=True,
                  user_home=tmp_path)
    actions.pkg_audit(_B(), ctx)
    ctx.output.print_summary()
    return capsys.readouterr().out


def test_findings_are_not_reported_with_a_green_tick(tmp_path, capsys):
    """A real host produced 46 findings under a `✓`. Findings are open items, not an
    accomplishment, and a green tick over them reads as "all good" at a glance."""
    from fettle.supplychain.base import Finding, Severity, UNOFFICIAL_SOURCE
    out = _audit_with([Finding(Severity.WARN, "test", "pkg", UNOFFICIAL_SOURCE, "x")],
                      capsys, tmp_path)
    assert "! 1 supply-chain finding(s)" in out
    assert "✓ 1 supply-chain" not in out


def test_a_critical_finding_stops_an_automated_run(tmp_path, capsys):
    """A known-malicious package is not a to-do item — this is the one read-only audit
    whose result should fail a scripted run."""
    from fettle import actions
    from fettle.backends.base import Context
    from fettle.config import Config
    from fettle.output import Output
    from fettle.supplychain.base import Finding, KNOWN_BAD, Severity

    class _P:
        source, coverage = "test", "cov"

        def is_present(self, ctx):
            return True

        def findings(self, ctx):
            return [Finding(Severity.CRIT, "test", "evil", KNOWN_BAD, "malicious")]

    class _B:
        def supply_chain_sources(self):
            return [_P()]

    ctx = Context(output=Output(color=False), config=Config(), dry_run=True,
                  user_home=tmp_path)
    actions.pkg_audit(_B(), ctx)
    assert ctx.output.had_failures is True


def test_clean_audit_still_reads_as_clean(tmp_path, capsys):
    out = _audit_with([], capsys, tmp_path)
    assert "no supply-chain findings" in out
