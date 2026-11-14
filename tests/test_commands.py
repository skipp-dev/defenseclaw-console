import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from console import commands as c  # noqa: E402


def test_argv_skill_block():
    assert c.build_argv("skill_block", "x") == ["skill", "block", "x"]


def test_argv_alert_and_tool():
    assert c.build_argv("alert_ack", "01a1-2b") == ["alerts", "acknowledge", "--id", "01a1-2b"]
    assert c.build_argv("tool_unblock", "Bash") == ["tool", "unblock", "Bash"]
    assert c.build_argv("plugin_restore", "p1") == ["plugin", "restore", "p1"]


def test_unknown_action():
    with pytest.raises(ValueError):
        c.build_argv("uninstall", "x")


def test_name_with_dash_rejected():
    for target in ["--all", "-y", "a;rm", "a b"]:
        with pytest.raises(ValueError):
            c.build_argv("skill_block", target)


def test_enforce_mode_without_confirmation():
    with pytest.raises(ValueError):
        c.build_argv("mode", "action")
    with pytest.raises(ValueError):
        c.build_argv("mode", "action", "enforce")


def test_enforce_mode_with_confirmation():
    assert c.build_argv("mode", "action", "ENFORCE") == ["guardrail", "mode", "action", "--connector", "claudecode"]
    assert c.build_argv("mode", "observe") == ["guardrail", "mode", "observe", "--connector", "claudecode"]
    with pytest.raises(ValueError):
        c.build_argv("mode", "broken", "ENFORCE")


def _fake_cli(tmp_path, body):
    p = tmp_path / "cli"
    p.write_text("#!/bin/bash\n" + body)
    p.chmod(0o755)
    return str(p)


def test_run_uses_no_shell(tmp_path):
    cli = _fake_cli(tmp_path, 'printf "%s\\n" "$@"\n')
    r = c.run(["skill", "block", "a;b"], cli, log=tmp_path / "c.log")
    assert r["ok"] and r["code"] == 0
    assert r["output"].splitlines() == ["skill", "block", "a;b"]
    assert "skill" in (tmp_path / "c.log").read_text()


def test_run_strips_colour_codes(tmp_path):
    cli = _fake_cli(tmp_path, 'printf "\\033[32mOK\\033[0m"\n')
    assert c.run([], cli, log=tmp_path / "c.log")["output"] == "OK"


def test_timeout_gives_ok_false(tmp_path):
    cli = _fake_cli(tmp_path, "sleep 5\n")
    r = c.run([], cli, timeout=1, log=tmp_path / "c.log")
    assert r["ok"] is False and r["code"] == -1
