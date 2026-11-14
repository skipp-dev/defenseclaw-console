import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from console import data as d  # noqa: E402

_SCHEMA = """CREATE TABLE audit_events (id TEXT PRIMARY KEY, timestamp TEXT, action TEXT,
 target TEXT, details TEXT, severity TEXT, session_id TEXT, tool_name TEXT, payload_json TEXT)"""


def _hd(i, sid, action, would, enforced, op="op-1", t="2026-11-14T11:00:00Z"):
    p = {"defenseclaw.guardrail.effective_action": action, "defenseclaw.guardrail.would_block": would,
         "defenseclaw.guardrail.enforced": enforced, "defenseclaw.hook.event": "PreToolUse",
         "defenseclaw.operation.id": op}
    return (f"hd{i}", t, "hook_decision", "", "", "INFO", sid, None, json.dumps(p))


def make_db(tmp_path, extra=()):
    p = tmp_path / "audit.db"
    c = sqlite3.connect(p)
    c.execute(_SCHEMA)
    rows = [
        _hd(1, "sessA", "allow", 0, 0), _hd(2, "sessA", "allow", 0, 0), _hd(3, "sessB", "allow", 0, 0),
        _hd(4, "sessB", "allow", 1, 0), _hd(5, "sessA", "block", 0, 1, t="2026-11-14T12:00:00Z"),
        ("ti1", "2026-11-14T11:00:01Z", "tool_invocation", "", "", "INFO", "sessA", "Bash",
         json.dumps({"gen_ai.tool.name": "Bash", "gen_ai.tool.call.arguments": '{"command":"<b>ls</b>"}',
                     "gen_ai.tool.call.result": "a\nb", "defenseclaw.operation.id": "op-1"})),
        ("lp1", "2026-11-14T11:00:02Z", "llm_prompt", "", "", "INFO", "sessB", None,
         json.dumps({"gen_ai.input.messages": '[{"parts":[{"content":"Hello","type":"text"}],"role":"user"}]'})),
        ("sf1", "2026-11-14T11:00:03Z", "scan-finding", "skillX", "Rule R1", "MEDIUM", None, None, "{}"),
        *extra,
    ]
    c.executemany("INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?)", rows)
    c.commit()
    c.close()
    return p


def _fake_cli(tmp_path, body):
    p = tmp_path / "cli"
    p.write_text("#!/bin/bash\n" + body)
    p.chmod(0o755)
    return str(p)


def test_counts_three_classes(tmp_path):
    z = d.counts(make_db(tmp_path), since_hours=None)
    assert (z["seen"], z["allowed"], z["would_block"], z["blocked"]) == (5, 3, 1, 1)
    assert z["per_session"]["sessA"]["blocked"] == 1
    assert z["per_session"]["sessB"]["would_block"] == 1
    assert [h["hour"] for h in z["per_hour"]] == ["2026-11-14T11", "2026-11-14T12"]


def test_counts_per_checkpoint(tmp_path):
    assert d.counts(make_db(tmp_path), since_hours=None)["per_checkpoint"] == {"PreToolUse": 5}


def test_unknown_verdict_is_not_counted_as_allowed(tmp_path):
    z = d.counts(make_db(tmp_path, [_hd(9, "sessA", "warn", 0, 0), _hd(10, "sessA", None, 0, 0)]), since_hours=None)
    assert (z["allowed"], z["unknown"]) == (3, 2)


def test_counts_non_text_session_id(tmp_path):
    p = {"defenseclaw.guardrail.effective_action": "allow", "gen_ai.conversation.id": 12345}
    row = ("hdx", "2026-11-14T11:00:00Z", "hook_decision", "", "", "INFO", None, None, json.dumps(p))
    assert d.counts(make_db(tmp_path, [row]), since_hours=None)["per_session"]["12345"]["seen"] == 1


def test_events_filter_session_and_summary_without_content(tmp_path):
    db = make_db(tmp_path)
    everything = d.events(db)["events"]
    assert {e["kind"] for e in everything} >= {"tool_invocation", "llm_prompt", "scan-finding", "hook_decision"}
    only_b = d.events(db, session="sessB")["events"]
    assert only_b and all(e["session"] == "sessB" for e in only_b)
    ti = next(e for e in everything if e["id"] == "ti1")
    assert ti["tool"] == "Bash" and "ls" not in ti["summary"] and "chars" in ti["summary"]
    assert next(e for e in everything if e["id"] == "hd5")["verdict"] == "blocked"


def test_events_filter_kind(tmp_path):
    only = d.events(make_db(tmp_path), kind="llm_prompt")["events"]
    assert [e["id"] for e in only] == ["lp1"] and "Hello" not in only[0]["summary"]


def test_events_filter_verdict_matches_tiles(tmp_path, monkeypatch):
    monkeypatch.setattr(d, "_since", lambda hours: "2026-11-14T10:00:00" if hours else "")
    old = _hd(9, "sessA", "block", 0, 1, t="2026-11-13T09:00:00Z")
    db = make_db(tmp_path, extra=[old])
    assert [e["id"] for e in d.events(db, verdict="would_block", kind="llm_prompt")["events"]] == ["hd4"]
    assert [e["id"] for e in d.events(db, verdict="blocked")["events"]] == ["hd5"]
    assert len(d.events(db, verdict="allowed", session="sessA", limit=1)["events"]) == 1
    assert len(d.events(db, verdict="bogus")["events"]) == 9


def test_summary_formats_large_numbers():
    assert d._summary("tool_invocation", None, {"gen_ai.tool.call.result": "x" * 12345}).startswith("tool result, 12,345 chars")


def test_event_with_related_rows_and_content(tmp_path):
    e = d.event(make_db(tmp_path), "ti1")
    assert e["row"]["contents"]["gen_ai.tool.call.result"] == "a\nb"
    assert {v["id"] for v in e["related"]} >= {"hd1", "hd2", "hd3", "hd4", "hd5"}


def test_event_truncates_huge_content(tmp_path):
    big = ("rb1", "2026-11-14T11:00:04Z", "tool_invocation", "", "", "INFO", "sessA", "Read",
           json.dumps({"gen_ai.tool.call.result": "x" * 300_000}))
    e = d.event(make_db(tmp_path, [big]), "rb1")
    assert len(e["row"]["contents"]["gen_ai.tool.call.result"]) == 200_000
    assert e["row"]["truncated_from"]["gen_ai.tool.call.result"] == 300_000


def test_event_unknown(tmp_path):
    assert d.event(make_db(tmp_path), "nope") == {"errors": ["not found"]}


def test_locked_db_reports_errors(tmp_path):
    db = make_db(tmp_path)
    lock = sqlite3.connect(db, isolation_level=None)
    lock.execute("PRAGMA locking_mode=EXCLUSIVE")
    lock.execute("BEGIN EXCLUSIVE")
    try:
        z = d.counts(db, since_hours=None, timeout=0.2)
        assert z["errors"] and z["seen"] == 0
        e = d.events(db, timeout=0.2)
        assert e["events"] == [] and e["errors"]
    finally:
        lock.execute("ROLLBACK")
        lock.close()


def test_checkpoints_from_settings(tmp_path):
    s = tmp_path / "settings.json"
    s.write_text(json.dumps({"hooks": {
        "PreToolUse": [{"hooks": [{"command": "/x/.defenseclaw/hooks/claude-code-hook.sh || true"}]},
                       {"hooks": [{"command": "/x/my-hook.sh"}]}],
        "Stop": [{"hooks": [{"command": "/x/my-stop.sh"}]}],
        "SessionEnd": [{"hooks": [{"command": "/x/.defenseclaw/hooks/claude-code-hook.sh"}]}]}}))
    assert d.checkpoints(s) == {"defenseclaw": ["PreToolUse", "SessionEnd"], "own": {"PreToolUse": 1, "Stop": 1}}


def test_checkpoints_null_command(tmp_path):
    s = tmp_path / "settings.json"
    s.write_text(json.dumps({"hooks": {"Stop": [{"hooks": [{"type": "http", "command": None}, {"url": "x"}]}]}}))
    assert d.checkpoints(s)["defenseclaw"] == []


def test_state_keeps_last_values_when_cli_fails(tmp_path):
    counter = tmp_path / "n"
    cli = _fake_cli(tmp_path, f'''n=$(cat {counter} 2>/dev/null || echo 0); echo $((n+1)) > {counter}
if [ "$n" -ge 5 ]; then exit 1; fi
case "$1" in status) echo '{{"sidecar":{{"running":true}},"connectors":[{{"mode":"observe"}}]}}';; *) echo '[]';; esac
''')
    config = tmp_path / "config.yaml"
    config.write_text("guardrail:\n  mode: observe\n")
    d._LAST.clear()
    z1 = d.state(cli, config=config)
    assert z1["reachable"] and z1["status"]["connectors"][0]["mode"] == "observe"
    assert "mode: observe" in z1["config"]
    z2 = d.state(cli, config=config)
    assert z2["reachable"] is False and z2["errors"]
    assert z2["status"]["connectors"][0]["mode"] == "observe"
    assert z2["as_of"] == z1["as_of"] and z2["part_as_of"]["status"] == z1["part_as_of"]["status"]


def test_stopped_gateway_is_not_reachable(tmp_path):
    cli = _fake_cli(tmp_path, 'case "$1" in status) echo \'{"sidecar":{"running":false}}\';; *) echo "[]";; esac\n')
    d._LAST.clear()
    assert d.state(cli, config=tmp_path / "x")["reachable"] is False
