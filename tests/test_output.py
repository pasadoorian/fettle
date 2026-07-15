from fettle.output import Output


def test_no_color_has_no_escape_sequences(capsys):
    out = Output(color=False)
    out.section("Hello")
    out.ok("done")
    captured = capsys.readouterr()
    assert "\033[" not in captured.out
    assert "Hello" in captured.out
    assert "done" in captured.out


def test_step_counter(capsys):
    out = Output(color=False)
    out.step_total = 2
    out.section("one")
    out.section("two")
    text = capsys.readouterr().out
    assert "[1/2] one" in text
    assert "[2/2] two" in text


def test_warn_and_err_go_to_stderr(capsys):
    out = Output(color=False)
    out.warn("careful")
    out.err("nope")
    cap = capsys.readouterr()
    assert "careful" in cap.err
    assert "nope" in cap.err
    assert cap.out == ""


def test_quiet_suppresses_status_but_not_warnings(capsys):
    out = Output(color=False, quiet=True)
    out.section("hidden")
    out.ok("hidden")
    out.warn("shown")
    cap = capsys.readouterr()
    assert "hidden" not in cap.out
    assert "shown" in cap.err


def test_summary_and_next_steps(capsys):
    out = Output(color=False)
    out.summary_add("did a thing")
    out.next_step("do the next thing")
    out.print_summary()
    text = capsys.readouterr().out
    assert "did a thing" in text
    assert "do the next thing" in text


def test_empty_summary_reports_nothing(capsys):
    out = Output(color=False)
    out.print_summary()
    assert "nothing to report" in capsys.readouterr().out


def test_tool_name_skips_env_and_var_wrappers():
    assert Output._tool_name(["env", "FOO=bar", "apt-get", "-y"]) == "apt-get"
    assert Output._tool_name(["yay", "-Sua"]) == "yay"
    assert Output._tool_name(["pacman", "-Syuu"]) == "pacman"


def test_run_streamed_frames_tool_output(capfd):
    # capfd (not capsys): run_streamed doesn't capture the tool — its output goes
    # to the fd directly (so interactive prompts still work).
    Output(color=False).run_streamed(["echo", "hi from the tool"])
    out = capfd.readouterr().out
    assert "output below is echo's, not fettle's" in out  # opening banner names the tool
    assert "hi from the tool" in out                       # the tool's own output streamed
    assert "end echo" in out                               # closing banner


def test_run_streamed_labels_real_tool_not_env(capsys):
    from unittest.mock import patch

    from fettle import command
    with patch("fettle.command.run", return_value=command.Proc(0)):
        Output(color=False).run_streamed(["env", "DEBIAN_FRONTEND=noninteractive",
                                          "apt-get", "full-upgrade"])
    out = capsys.readouterr().out
    assert "apt-get" in out and "output below is apt-get's" in out
